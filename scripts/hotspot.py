#!/usr/bin/env python3
"""Wi-Fi hotspot backend for the mlhunter.hotspot Omarchy plugin.

CLI usage (invoked by BarWidget.qml through Quickshell's Process element):
    hotspot.py up              # start the hotspot (creates the profile on first use)
    hotspot.py down            # stop it
    hotspot.py toggle          # up if down, down if up
    hotspot.py apply k=v ...   # ssid=, band=bg|a, security=wpa|wpa2|wpa3;
                               # a new password, if any, is read from stdin
    hotspot.py show-password   # print the stored password (for the panel's eye)
    hotspot.py status          # print one JSON snapshot
    hotspot.py watch           # stream JSON snapshots, one line per change

NetworkManager does the real work. The plugin owns exactly one connection
profile, PROFILE_NAME, in access-point mode with ipv4.method=shared, so NM
brings up the AP, DHCP and NAT onto whatever uplink is connected.

Secrets: the password lives only in that NM profile. It reaches us on stdin,
never argv, and is handed to nmcli's connection editor on stdin as well, so
it never shows up in /proc/*/cmdline. Snapshots carry no password; the panel
asks for it explicitly with show-password.

Filesystem model (same as mlhunter.pomodoro): every file this script touches
lives in one private, owner-only directory that is opened once and then
addressed exclusively through the retained directory descriptor (StateDir).
Files are opened O_NOFOLLOW|O_NONBLOCK, must be regular and owned by us,
reads are byte-bounded and values re-validated against a fixed schema.
Writes go through an O_EXCL temporary and rename(2). Commands serialise on
state.lock. Child processes are fixed absolute, root-owned executables run
under a closed environment in their own process group.
"""
import contextlib
import errno
import fcntl
import json
import os
import pwd
import secrets
import signal
import stat
import string
import subprocess
import sys
import time

STATE_DIR_RELATIVE = ".local/state/omarchy/hotspot"
CONFIG_NAME = "config.json"
STATE_NAME = "state.json"
STATE_LOCK_NAME = "state.lock"

PROFILE_NAME = "Omarchy Hotspot"

MAX_FILE_BYTES = 64 * 1024
MAX_ENV_VALUE_BYTES = 4096
MAX_CHILD_OUTPUT_BYTES = 256 * 1024
MAX_ERROR_CHARS = 240
MAX_PASSWORD_INPUT_BYTES = 1024

LOCK_TIMEOUT_SECONDS = 90.0
CHILD_TIMEOUT_SECONDS = 10.0
ACTIVATE_TIMEOUT_SECONDS = 60.0
CHILD_KILL_GRACE_SECONDS = 2.0
WATCH_POLL_SECONDS = 1.5
WATCH_SLOW_REFRESH_SECONDS = 30.0
RESCAN_SETTLE_SECONDS = 5.0

BANDS = ("bg", "a")
SECURITY_MODES = ("wpa", "wpa2", "wpa3")

# What each security choice means to NetworkManager. pmf: 1 = disable,
# 3 = required (WPA3/SAE mandates protected management frames).
SECURITY_SETTINGS = {
    "wpa": {"key-mgmt": "wpa-psk", "proto": "wpa", "pairwise": "tkip", "group": "tkip", "pmf": "1"},
    "wpa2": {"key-mgmt": "wpa-psk", "proto": "rsn", "pairwise": "ccmp", "group": "ccmp", "pmf": "1"},
    "wpa3": {"key-mgmt": "sae", "proto": "rsn", "pairwise": "ccmp", "group": "ccmp", "pmf": "3"},
}

DEFAULT_CONFIG = {
    "ssid": "Omarchy Hotspot",
    "band": "bg",
    "security": "wpa2",
}

GENERATED_PASSWORD_LENGTH = 12
GENERATED_PASSWORD_ALPHABET = string.ascii_letters + string.digits

REGDOM_HINT = ("5 GHz is blocked until your country is set: uncomment your country in "
               "/etc/conf.d/wireless-regdom (or run: sudo iw reg set XX), then retry")
CARD_5GHZ_HINT = ("This Wi-Fi card isn't allowing any 5 GHz channel for hosting right now "
                  "(its firmware marks them all no-IR). Use 2.4 GHz")

# Fixed child identities. Nothing is resolved through PATH.
NMCLI_CANDIDATES = ("/usr/bin/nmcli", "/bin/nmcli")
IW_CANDIDATES = ("/usr/bin/iw", "/usr/sbin/iw", "/sbin/iw")
DNSMASQ_CANDIDATES = ("/usr/bin/dnsmasq", "/usr/sbin/dnsmasq")

DNSMASQ_HINT = "Sharing needs dnsmasq, which is not installed: sudo pacman -S dnsmasq"

PASSTHROUGH_ENV = (
    "DBUS_SYSTEM_BUS_ADDRESS",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
)


class StateDirError(RuntimeError):
    """The state directory or one of its files is not what it must be."""


class HotspotError(RuntimeError):
    """A user-facing failure, shown in the panel as-is."""


# ---------------------------------------------------------------------------
# Private, descriptor-retained state directory
# ---------------------------------------------------------------------------

def home_directory():
    """The user's home, from the passwd entry when $HOME is unusable."""
    home = os.environ.get("HOME", "")
    if not home or not os.path.isabs(home):
        try:
            home = pwd.getpwuid(os.geteuid()).pw_dir
        except KeyError:
            home = ""
    if not home or not os.path.isabs(home):
        raise StateDirError("cannot determine an absolute home directory")
    return home


class StateDir:
    """One private directory, held open for the life of the process.

    The directory is created 0700 and then opened O_DIRECTORY|O_NOFOLLOW; the
    descriptor is kept and every later open/rename/unlink is relative to it.
    """

    def __init__(self, path=None):
        self.path = path or os.path.join(home_directory(), STATE_DIR_RELATIVE)
        self.fd = self._open_private_dir(self.path)

    @staticmethod
    def _open_private_dir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise StateDirError("cannot open %s privately: %s" % (path, exc))
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise StateDirError("%s is not a directory" % path)
            if info.st_uid != os.geteuid():
                raise StateDirError("%s is not owned by this user" % path)
            if info.st_mode & 0o077:
                os.fchmod(fd, 0o700)
                if os.fstat(fd).st_mode & 0o077:
                    raise StateDirError("%s stays group/world accessible" % path)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read_text(self, name):
        """Read one of our fixed names, no-follow and byte-bounded."""
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=self.fd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StateDirError("%s is not a regular file" % name)
            if info.st_uid != os.geteuid():
                raise StateDirError("%s is not owned by this user" % name)
            if info.st_size > MAX_FILE_BYTES:
                raise StateDirError("%s exceeds %d bytes" % (name, MAX_FILE_BYTES))
            chunks = []
            total = 0
            while total <= MAX_FILE_BYTES:
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise StateDirError("%s exceeds %d bytes" % (name, MAX_FILE_BYTES))
            return b"".join(chunks).decode("utf-8")
        finally:
            os.close(fd)

    def read_json(self, name):
        """Parsed JSON for one of our names, or None if it is unusable."""
        try:
            raw = self.read_text(name)
        except (OSError, StateDirError, UnicodeDecodeError):
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def write_json(self, name, payload):
        """Replace one of our names atomically, via an O_EXCL sibling."""
        data = json.dumps(payload, indent=2).encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise StateDirError("refusing to write %d bytes to %s" % (len(data), name))

        tmp = ".%s.%d.%s.tmp" % (name, os.getpid(), os.urandom(8).hex())
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        try:
            try:
                handle = os.fdopen(fd, "wb", closefd=True)
            except BaseException:
                os.close(fd)
                raise
            with handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=self.fd)
            raise
        with contextlib.suppress(OSError):
            os.fsync(self.fd)

    def open_lock(self, name):
        """A private lock file in this directory, opened for flock(2)."""
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StateDirError("%s is not a regular file" % name)
            if info.st_uid != os.geteuid():
                raise StateDirError("%s is not owned by this user" % name)
        except BaseException:
            os.close(fd)
            raise
        return fd


def try_flock(fd):
    """Take an exclusive flock without waiting. False if someone else holds it."""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            return False
        raise
    return True


def wait_for_flock(fd, timeout=LOCK_TIMEOUT_SECONDS):
    """Take an exclusive flock, giving up after timeout seconds."""
    deadline = time.monotonic() + timeout
    while True:
        if try_flock(fd):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


@contextlib.contextmanager
def state_lock(store, timeout=LOCK_TIMEOUT_SECONDS):
    """Serialise every command that touches NM or our files."""
    fd = store.open_lock(STATE_LOCK_NAME)
    try:
        if not wait_for_flock(fd, timeout):
            raise StateDirError("timed out waiting for the state lock")
        yield
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _has_control_chars(text):
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text)


def validate_ssid(value):
    if not isinstance(value, str) or _has_control_chars(value):
        raise HotspotError("Name must be plain text")
    size = len(value.encode("utf-8"))
    if size < 1 or size > 32:
        raise HotspotError("Name must be 1-32 bytes long")
    if value != value.strip():
        raise HotspotError("Name cannot start or end with a space")
    return value


def validate_password(value):
    """WPA passphrase: 8-63 printable ASCII, no surrounding spaces.

    Surrounding spaces are refused because nmcli's editor trims them, which
    would silently store a different password from the one the user typed.
    """
    if not isinstance(value, str):
        raise HotspotError("Password must be text")
    if len(value) < 8 or len(value) > 63:
        raise HotspotError("Password must be 8-63 characters")
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
        raise HotspotError("Password may only use printable ASCII characters")
    if value != value.strip():
        raise HotspotError("Password cannot start or end with a space")
    return value


def validate_band(value):
    if value not in BANDS:
        raise HotspotError("Band must be bg (2.4 GHz) or a (5 GHz)")
    return value


def validate_security(value):
    if value not in SECURITY_MODES:
        raise HotspotError("Security must be one of: %s" % ", ".join(SECURITY_MODES))
    return value


VALIDATORS = {
    "ssid": validate_ssid,
    "band": validate_band,
    "security": validate_security,
}


def sanitize_config(raw):
    """Coerce whatever config.json held into the exact schema."""
    config = dict(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        for key, check in VALIDATORS.items():
            if key in raw:
                try:
                    config[key] = check(raw[key])
                except HotspotError:
                    pass
    return config


def parse_apply_args(args):
    """k=v pairs → validated updates. Unknown or repeated keys are refused."""
    updates = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        if not sep or key not in VALIDATORS:
            raise HotspotError("unknown setting: %s" % key)
        if key in updates:
            raise HotspotError("setting given twice: %s" % key)
        updates[key] = VALIDATORS[key](value)
    return updates


def load_config(store):
    return sanitize_config(store.read_json(CONFIG_NAME))


def save_config(store, config):
    store.write_json(CONFIG_NAME, sanitize_config(config))


def load_error(store):
    raw = store.read_json(STATE_NAME)
    if isinstance(raw, dict) and isinstance(raw.get("error"), str):
        return clean_message(raw["error"])
    return ""


def save_error(store, message):
    store.write_json(STATE_NAME, {"error": clean_message(message)})


def clean_message(text):
    """One short printable line, safe to render in the panel."""
    if not isinstance(text, str):
        return ""
    # nmcli puts the real failure on its "Error:" line and follows it with a
    # journalctl "Hint:" that means nothing in a panel, so prefer the former.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = [line for line in lines if line.lower().startswith("error: ")]
    line = errors[0][7:] if errors else (lines[0] if lines else "")
    if line.startswith("Connection activation failed: "):
        line = line[len("Connection activation failed: "):]
    line = "".join(ch for ch in line if ch.isprintable())
    return line[:MAX_ERROR_CHARS]


def generate_password():
    return "".join(secrets.choice(GENERATED_PASSWORD_ALPHABET)
                   for _ in range(GENERATED_PASSWORD_LENGTH))


# ---------------------------------------------------------------------------
# Child processes: fixed identities, closed environment, own process group
# ---------------------------------------------------------------------------

def trusted_program(candidates):
    """The first candidate that is a root-owned, non-world-writable executable."""
    for path in candidates:
        try:
            info = os.stat(path)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_uid != 0:
            continue
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        if not os.access(path, os.X_OK):
            continue
        return path
    return None


def child_environment():
    """A closed environment: a fixed PATH plus the few bus handles nmcli needs."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": home_directory(),
        "LC_ALL": "C.UTF-8",
    }
    for key in PASSTHROUGH_ENV:
        value = os.environ.get(key)
        if not value or len(value) > MAX_ENV_VALUE_BYTES:
            continue
        if "\x00" in value or "\n" in value:
            continue
        env[key] = value
    return env


def _terminate_group(proc):
    """Tear down a child and anything it forked, as one process group."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            break
        try:
            proc.wait(timeout=CHILD_KILL_GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=CHILD_KILL_GRACE_SECONDS)


def run_capture(argv, stdin_text=None, timeout=CHILD_TIMEOUT_SECONDS):
    """Run a fixed-identity helper, bounded and reaped. Returns (rc, out, err)."""
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment(),
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)
    try:
        data = stdin_text.encode("utf-8") if stdin_text is not None else None
        out, err = proc.communicate(input=data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_group(proc)
        return 124, "", "%s timed out" % os.path.basename(argv[0])
    out = out[:MAX_CHILD_OUTPUT_BYTES].decode("utf-8", "replace")
    err = err[:MAX_CHILD_OUTPUT_BYTES].decode("utf-8", "replace")
    return proc.returncode, out, err


def nmcli(*args, stdin_text=None, timeout=CHILD_TIMEOUT_SECONDS):
    program = trusted_program(NMCLI_CANDIDATES)
    if program is None:
        raise HotspotError("nmcli (NetworkManager) is not installed")
    return run_capture([program] + list(args), stdin_text=stdin_text, timeout=timeout)


def nmcli_ok(*args, stdin_text=None, timeout=CHILD_TIMEOUT_SECONDS):
    rc, out, err = nmcli(*args, stdin_text=stdin_text, timeout=timeout)
    if rc != 0:
        raise HotspotError(clean_message(err) or "nmcli failed (exit %d)" % rc)
    return out


def iw(*args):
    program = trusted_program(IW_CANDIDATES)
    if program is None:
        return 127, "", "iw is not installed"
    return run_capture([program] + list(args))


def split_terse(line):
    """Split one nmcli -t/-g line on unescaped ':' and unescape the fields."""
    fields, current, escaped = [], [], False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


# ---------------------------------------------------------------------------
# Reading the system
# ---------------------------------------------------------------------------

def parse_regdomain(text):
    """Country code from `iw reg get`'s global section, or "" if unknown."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("country ") and ":" in line:
            return line[len("country "):line.index(":")].strip()
    return ""


def regdomain_allows_5ghz(code):
    # "00" is the world domain: every 5 GHz channel is no-IR, so no AP there.
    return bool(code) and code != "00"


def read_regdomain():
    rc, out, _ = iw("reg", "get")
    return parse_regdomain(out) if rc == 0 else ""


def parse_wiphy(text):
    """The phy index from `iw dev X info`, or None."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "wiphy" and parts[1].isdigit():
            return parts[1]
    return None


def usable_5ghz_channels(text):
    """5 GHz channel numbers in `iw phy X info` that may actually transmit.

    The global country is not enough: some cards (e.g. ath10k with a
    world-roaming EEPROM) keep their own per-phy domain that marks 5 GHz
    channels "no IR" whatever the OS country says, lifting it per channel only
    after hearing another AP there. Only channels free of no-IR, disabled and
    radar flags can host an AP without DFS.
    """
    channels = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("* 5") or " MHz" not in line or "[" not in line:
            continue
        lowered = line.lower()
        if "no ir" in lowered or "disabled" in lowered or "radar" in lowered:
            continue
        number = line[line.index("[") + 1:line.find("]")]
        if number.isdigit():
            channels.append(int(number))
    return channels


def five_ghz_status(interface):
    """(allowed, reason, channel) for hosting on 5 GHz with this card here.

    channel is the first one the card will transmit on right now; the profile
    is pinned to it, because NM's automatic pick can land on a no-IR channel
    and then fail with an unrelated-sounding "supplicant took too long".
    """
    regdomain = read_regdomain()
    if not regdomain_allows_5ghz(regdomain):
        return False, REGDOM_HINT, None
    rc, out, _ = iw("dev", interface, "info") if interface else (1, "", "")
    phy = parse_wiphy(out) if rc == 0 else None
    if phy is None:
        return False, "Could not read this Wi-Fi card's channel list", None
    rc, out, _ = iw("phy", "phy" + phy, "info")
    channels = usable_5ghz_channels(out) if rc == 0 else []
    if not channels:
        return False, CARD_5GHZ_HINT, None
    return True, "", channels[0]


def find_ap_interface():
    """The first Wi-Fi device whose driver supports access-point mode."""
    rc, out, _ = nmcli("-g", "DEVICE,TYPE", "device")
    if rc != 0:
        return ""
    for line in out.splitlines():
        fields = split_terse(line)
        if len(fields) != 2 or fields[1] != "wifi":
            continue
        dev_rc, ap, _ = nmcli("-g", "WIFI-PROPERTIES.AP", "device", "show", fields[0])
        if dev_rc == 0 and ap.strip() == "yes":
            return fields[0]
    return ""


def profile_state():
    """(exists, active) for our NM profile."""
    rc, out, _ = nmcli("-g", "NAME,ACTIVE", "connection", "show")
    if rc != 0:
        return False, False
    for line in out.splitlines():
        fields = split_terse(line)
        if len(fields) == 2 and fields[0] == PROFILE_NAME:
            return True, fields[1] == "yes"
    return False, False


def count_clients(interface):
    if not interface:
        return 0
    rc, out, _ = iw("dev", interface, "station", "dump")
    if rc != 0:
        return 0
    return sum(1 for line in out.splitlines() if line.startswith("Station "))


# ---------------------------------------------------------------------------
# Writing the NM profile
# ---------------------------------------------------------------------------

def security_args(mode):
    settings = SECURITY_SETTINGS[mode]
    return [
        "802-11-wireless-security.key-mgmt", settings["key-mgmt"],
        "802-11-wireless-security.proto", settings["proto"],
        "802-11-wireless-security.pairwise", settings["pairwise"],
        "802-11-wireless-security.group", settings["group"],
        "802-11-wireless-security.pmf", settings["pmf"],
    ]


def profile_args(config, interface):
    """Every non-secret property we own, as nmcli key/value pairs."""
    return [
        "connection.interface-name", interface,
        "connection.autoconnect", "no",
        "802-11-wireless.ssid", config["ssid"],
        "802-11-wireless.mode", "ap",
        "802-11-wireless.band", config["band"],
        # Back to automatic; activate() pins a usable channel for 5 GHz.
        "802-11-wireless.channel", "",
        "ipv4.method", "shared",
        "ipv6.method", "disabled",
    ] + security_args(config["security"])


def editor_script(password):
    """Commands for `nmcli connection edit`, which reads them from stdin."""
    return "set 802-11-wireless-security.psk %s\nsave persistent\nquit\n" % password


def write_profile(config, interface, password=None):
    """Create or update our profile. Returns True if it was newly created."""
    exists, _ = profile_state()
    if exists:
        nmcli_ok("connection", "modify", PROFILE_NAME, *profile_args(config, interface))
        created = False
    else:
        nmcli_ok("connection", "add", "type", "wifi", "con-name", PROFILE_NAME,
                 *profile_args(config, interface))
        created = True
        if password is None:
            password = generate_password()
    if password is not None:
        set_password(password)
    return created


def set_password(password):
    validate_password(password)
    nmcli_ok("connection", "edit", "id", PROFILE_NAME, stdin_text=editor_script(password))


def read_password():
    out = nmcli_ok("-s", "-g", "802-11-wireless-security.psk", "connection", "show", PROFILE_NAME)
    return split_terse(out.rstrip("\n"))[0] if out else ""


def require_interface():
    interface = find_ap_interface()
    if not interface:
        raise HotspotError("No Wi-Fi adapter with access-point support was found")
    return interface


def five_ghz_status_after_rescan(interface):
    """five_ghz_status once more, after letting the card listen again.

    Cards that only unlock a 5 GHz channel after hearing another AP on it
    forget that while they are themselves hosting (an AP doesn't scan), so a
    restart from 2.4 GHz or another 5 GHz setup finds every channel no-IR
    again. Stop our AP, rescan, and give the regulatory hints time to land.
    """
    _, active = profile_state()
    if active:
        nmcli("connection", "down", PROFILE_NAME, timeout=ACTIVATE_TIMEOUT_SECONDS)
    nmcli("device", "wifi", "rescan", "ifname", interface)
    time.sleep(RESCAN_SETTLE_SECONDS)
    return five_ghz_status(interface)


def activate(config, interface):
    # ipv4.method=shared runs dnsmasq for DHCP/DNS; without it NM brings the
    # AP up and then fails with an opaque "IP configuration" error.
    if trusted_program(DNSMASQ_CANDIDATES) is None:
        raise HotspotError(DNSMASQ_HINT)
    if config["band"] == "a":
        allowed, reason, channel = five_ghz_status(interface)
        if not allowed and reason == CARD_5GHZ_HINT:
            allowed, reason, channel = five_ghz_status_after_rescan(interface)
        if not allowed:
            raise HotspotError(reason)
        nmcli_ok("connection", "modify", PROFILE_NAME, "802-11-wireless.channel", str(channel))
    nmcli_ok("connection", "up", PROFILE_NAME, timeout=ACTIVATE_TIMEOUT_SECONDS)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_up(store):
    config = load_config(store)
    interface = require_interface()
    write_profile(config, interface)
    activate(config, interface)


def cmd_down(store):
    _, active = profile_state()
    if active:
        nmcli_ok("connection", "down", PROFILE_NAME, timeout=ACTIVATE_TIMEOUT_SECONDS)


def cmd_toggle(store):
    _, active = profile_state()
    if active:
        cmd_down(store)
    else:
        cmd_up(store)


def read_stdin_password():
    """A new password from stdin, or None when none was sent.

    Exactly one bounded line is read rather than reading to EOF: the panel
    writes "password\\n" (or a bare "\\n" for "keep the current one") and may
    leave the pipe open, so waiting for EOF could hang.
    """
    if sys.stdin is None or sys.stdin.closed:
        return None
    try:
        data = sys.stdin.buffer.readline(MAX_PASSWORD_INPUT_BYTES + 1)
    except (OSError, ValueError):
        return None
    if len(data) > MAX_PASSWORD_INPUT_BYTES:
        raise HotspotError("Password input is too long")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise HotspotError("Password may only use printable ASCII characters")
    text = text.rstrip("\n").rstrip("\r")
    return text if text else None


def cmd_apply(store, args, password):
    updates = parse_apply_args(args)
    if password is not None:
        validate_password(password)
    config = load_config(store)
    config.update(updates)
    save_config(store, config)

    _, active = profile_state()
    interface = require_interface()
    write_profile(config, interface, password)
    if active:
        # A full stop before restarting: re-activating straight from one AP
        # setup into another times out on some cards (seen on ath10k), and a
        # stopped card can rescan for usable 5 GHz channels.
        nmcli_ok("connection", "down", PROFILE_NAME, timeout=ACTIVATE_TIMEOUT_SECONDS)
        activate(config, interface)


def snapshot(config, exists, active, interface, regdomain, five_ghz, clients, error):
    return {
        "active": bool(active),
        "configured": bool(exists),
        "ssid": config["ssid"],
        "band": config["band"],
        "security": config["security"],
        "interface": interface,
        "clients": int(clients),
        "regdomain": regdomain,
        "five_ghz_ok": bool(five_ghz[0]),
        "five_ghz_reason": five_ghz[1],
        "error": error,
    }


def cmd_watch(store):
    """Stream one JSON snapshot per change on stdout."""
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    last_line = None
    interface, regdomain, five_ghz, slow_at = "", "", (False, ""), 0.0
    while not _stopping:
        now = time.monotonic()
        if now - slow_at >= WATCH_SLOW_REFRESH_SECONDS or not interface:
            interface = find_ap_interface()
            regdomain = read_regdomain()
            five_ghz = five_ghz_status(interface)
            slow_at = now
        exists, active = profile_state()
        clients = count_clients(interface) if active else 0
        payload = snapshot(load_config(store), exists, active, interface, regdomain,
                           five_ghz, clients, load_error(store))
        line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if line != last_line:
            last_line = line
            try:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                return 0
        time.sleep(WATCH_POLL_SECONDS)
    return 0


def cmd_status(store):
    exists, active = profile_state()
    interface = find_ap_interface()
    clients = count_clients(interface) if active else 0
    payload = snapshot(load_config(store), exists, active, interface, read_regdomain(),
                       five_ghz_status(interface), clients, load_error(store))
    print(json.dumps(payload, sort_keys=True))
    return 0


_stopping = False


def _request_stop(_signum, _frame):
    global _stopping
    _stopping = True


LOCKED_COMMANDS = {
    "up": cmd_up,
    "down": cmd_down,
    "toggle": cmd_toggle,
}

USAGE = "usage: hotspot.py {up|down|toggle|apply k=v ...|show-password|status|watch}"


def run_locked(store, action):
    """Run one state-changing command; its outcome becomes the panel's error line."""
    with state_lock(store):
        try:
            action()
        except HotspotError as exc:
            save_error(store, str(exc))
            print("hotspot: %s" % exc, file=sys.stderr)
            return 1
        save_error(store, "")
    return 0


def main(argv):
    if len(argv) < 2:
        print(USAGE, file=sys.stderr)
        return 1

    command = argv[1]
    known = set(LOCKED_COMMANDS) | {"apply", "show-password", "status", "watch"}
    if command not in known:
        print("unknown command: %s" % command, file=sys.stderr)
        return 1

    try:
        store = StateDir()
    except (OSError, StateDirError) as exc:
        print("hotspot: %s" % exc, file=sys.stderr)
        return 1

    try:
        if command == "watch":
            return cmd_watch(store)
        if command == "status":
            return cmd_status(store)
        if command == "show-password":
            try:
                print(read_password())
            except HotspotError as exc:
                print("hotspot: %s" % exc, file=sys.stderr)
                return 1
            return 0
        if command == "apply":
            try:
                password = read_stdin_password()
            except HotspotError as exc:
                with state_lock(store):
                    save_error(store, str(exc))
                print("hotspot: %s" % exc, file=sys.stderr)
                return 1
            return run_locked(store, lambda: cmd_apply(store, argv[2:], password))
        return run_locked(store, lambda: LOCKED_COMMANDS[command](store))
    except (OSError, StateDirError) as exc:
        print("hotspot: %s" % exc, file=sys.stderr)
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
