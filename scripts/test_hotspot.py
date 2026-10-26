#!/usr/bin/env python3
"""Unit tests for hotspot.py: input validation, the security → nmcli
mapping, parsing of nmcli/iw output, and the private state directory.
nmcli itself is never run; the functions that call it are patched.

Runs with the stdlib only: python3 scripts/test_hotspot.py
"""
import io
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

import hotspot
from hotspot import (
    CONFIG_NAME,
    DEFAULT_CONFIG,
    PROFILE_NAME,
    STATE_NAME,
    HotspotError,
    StateDir,
    StateDirError,
    clean_message,
    usable_5ghz_channels,
    editor_script,
    parse_apply_args,
    parse_regdomain,
    parse_wiphy,
    profile_args,
    regdomain_allows_5ghz,
    sanitize_config,
    security_args,
    split_terse,
    validate_password,
    validate_ssid,
)


PHY_NO_IR = """\
\tBand 1:
\t\t\t* 2412.0 MHz [1] (20.0 dBm)
\tBand 2:
\t\t\t* 5180.0 MHz [36] (23.0 dBm) (no IR)
\t\t\t* 5260.0 MHz [52] (23.0 dBm) (no IR, radar detection)
"""

PHY_USABLE = """\
\tBand 2:
\t\t\t* 5180.0 MHz [36] (23.0 dBm)
\t\t\t* 5260.0 MHz [52] (23.0 dBm) (radar detection)
\t\t\t* 5845.0 MHz [169] (disabled)
"""


def pairs(args):
    """nmcli key/value argument list → dict."""
    return dict(zip(args[0::2], args[1::2]))


class ValidationTests(unittest.TestCase):
    def test_ssid_accepts_normal_and_unicode_names(self):
        self.assertEqual(validate_ssid("My Hotspot"), "My Hotspot")
        self.assertEqual(validate_ssid("café"), "café")

    def test_ssid_length_is_counted_in_bytes(self):
        validate_ssid("a" * 32)
        with self.assertRaises(HotspotError):
            validate_ssid("a" * 33)
        with self.assertRaises(HotspotError):
            validate_ssid("é" * 17)  # 34 bytes

    def test_ssid_rejects_empty_control_chars_and_padding(self):
        for bad in ("", "a\nb", "tab\there", " padded", "padded ", None, 5):
            with self.assertRaises(HotspotError, msg=repr(bad)):
                validate_ssid(bad)

    def test_password_length_bounds(self):
        validate_password("12345678")
        validate_password("x" * 63)
        for bad in ("1234567", "x" * 64):
            with self.assertRaises(HotspotError):
                validate_password(bad)

    def test_password_allows_symbols_and_inner_spaces(self):
        self.assertEqual(validate_password("Te5t:pa\\ss word"), "Te5t:pa\\ss word")

    def test_password_rejects_non_ascii_control_and_padding(self):
        for bad in ("pässwörd1", "pass\nword", "pass\x00word", " password", "password "):
            with self.assertRaises(HotspotError, msg=repr(bad)):
                validate_password(bad)

    def test_parse_apply_args_validates_every_key(self):
        self.assertEqual(
            parse_apply_args(["ssid=Net", "band=a", "security=wpa3"]),
            {"ssid": "Net", "band": "a", "security": "wpa3"},
        )
        for bad in (["band=5"], ["security=wep"], ["password=12345678"],
                    ["ssid"], ["ssid=a", "ssid=b"], ["interface=eth0"]):
            with self.assertRaises(HotspotError, msg=repr(bad)):
                parse_apply_args(bad)

    def test_parse_apply_keeps_equals_signs_in_value(self):
        self.assertEqual(parse_apply_args(["ssid=a=b"]), {"ssid": "a=b"})

    def test_sanitize_config_falls_back_per_key(self):
        cfg = sanitize_config({"ssid": "Ok", "band": "z", "security": "wep", "extra": 1})
        self.assertEqual(cfg, {"ssid": "Ok", "band": DEFAULT_CONFIG["band"],
                               "security": DEFAULT_CONFIG["security"]})
        self.assertEqual(sanitize_config(None), DEFAULT_CONFIG)
        self.assertEqual(sanitize_config([1, 2]), DEFAULT_CONFIG)


class SecurityMappingTests(unittest.TestCase):
    def test_wpa_is_legacy_tkip(self):
        s = pairs(security_args("wpa"))
        self.assertEqual(s["802-11-wireless-security.key-mgmt"], "wpa-psk")
        self.assertEqual(s["802-11-wireless-security.proto"], "wpa")
        self.assertEqual(s["802-11-wireless-security.pairwise"], "tkip")

    def test_wpa2_is_rsn_ccmp(self):
        s = pairs(security_args("wpa2"))
        self.assertEqual(s["802-11-wireless-security.key-mgmt"], "wpa-psk")
        self.assertEqual(s["802-11-wireless-security.proto"], "rsn")
        self.assertEqual(s["802-11-wireless-security.pairwise"], "ccmp")

    def test_wpa3_is_sae_with_required_pmf(self):
        s = pairs(security_args("wpa3"))
        self.assertEqual(s["802-11-wireless-security.key-mgmt"], "sae")
        self.assertEqual(s["802-11-wireless-security.pmf"], "3")

    def test_profile_args_are_a_shared_ap_that_never_autoconnects(self):
        cfg = dict(DEFAULT_CONFIG, ssid="Net", band="a")
        p = pairs(profile_args(cfg, "wlan0"))
        self.assertEqual(p["802-11-wireless.mode"], "ap")
        self.assertEqual(p["802-11-wireless.band"], "a")
        self.assertEqual(p["802-11-wireless.ssid"], "Net")
        self.assertEqual(p["ipv4.method"], "shared")
        self.assertEqual(p["connection.autoconnect"], "no")
        self.assertEqual(p["connection.interface-name"], "wlan0")
        self.assertEqual(p["802-11-wireless.channel"], "")  # automatic

    def test_password_never_appears_in_profile_args(self):
        args = profile_args(dict(DEFAULT_CONFIG), "wlan0")
        self.assertNotIn("802-11-wireless-security.psk", args)

    def test_editor_script_sets_psk_and_saves(self):
        script = editor_script("secret pass")
        self.assertEqual(script.splitlines(),
                         ["set 802-11-wireless-security.psk secret pass",
                          "save persistent", "quit"])


class ParsingTests(unittest.TestCase):
    def test_split_terse_handles_escapes(self):
        self.assertEqual(split_terse("Omarchy Hotspot:yes"), ["Omarchy Hotspot", "yes"])
        self.assertEqual(split_terse(r"a\:b:c\\d"), ["a:b", "c\\d"])

    def test_parse_regdomain(self):
        self.assertEqual(parse_regdomain("global\ncountry 00: DFS-UNSET\n\t(2402 - 2472 @ 40)"), "00")
        self.assertEqual(parse_regdomain("global\ncountry DE: DFS-ETSI\n"), "DE")
        self.assertEqual(parse_regdomain(""), "")

    def test_parse_wiphy(self):
        self.assertEqual(parse_wiphy("Interface wlp3s0\n\tifindex 4\n\twiphy 0\n"), "0")
        self.assertIsNone(parse_wiphy("Interface wlp3s0\n"))

    def test_usable_5ghz_channels_skips_no_ir_disabled_and_radar(self):
        self.assertEqual(usable_5ghz_channels(PHY_NO_IR), [])
        self.assertEqual(usable_5ghz_channels(PHY_USABLE), [36])

    def test_world_domain_blocks_5ghz(self):
        self.assertFalse(regdomain_allows_5ghz("00"))
        self.assertFalse(regdomain_allows_5ghz(""))
        self.assertTrue(regdomain_allows_5ghz("US"))

    def test_clean_message_prefers_error_line_over_hint(self):
        text = ("Error: Connection activation failed: IP configuration could not be reserved\n"
                "Hint: use 'journalctl -xe NM_CONNECTION=x' to get more details.\n")
        self.assertEqual(clean_message(text), "IP configuration could not be reserved")

    def test_clean_message_is_bounded_and_printable(self):
        self.assertEqual(clean_message("a\x1bb"), "ab")
        self.assertLessEqual(len(clean_message("x" * 1000)), hotspot.MAX_ERROR_CHARS)
        self.assertEqual(clean_message(None), "")


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = StateDir(os.path.join(self.tmp.name, "state"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_apply_saves_config_and_writes_profile_with_password(self):
        calls = []
        with mock.patch.object(hotspot, "profile_state", return_value=(True, False)), \
             mock.patch.object(hotspot, "find_ap_interface", return_value="wlan0"), \
             mock.patch.object(hotspot, "nmcli_ok", side_effect=lambda *a, **k: calls.append((a, k)) or ""):
            hotspot.cmd_apply(self.store, ["ssid=Net", "security=wpa3"], "goodpassword")
        self.assertEqual(hotspot.load_config(self.store)["ssid"], "Net")
        self.assertEqual(calls[0][0][:3], ("connection", "modify", PROFILE_NAME))
        edit_args, edit_kwargs = calls[1]
        self.assertEqual(edit_args[:2], ("connection", "edit"))
        self.assertIn("goodpassword", edit_kwargs["stdin_text"])
        for args, _ in calls:
            self.assertNotIn("goodpassword", args)  # never on argv

    def test_apply_restarts_running_hotspot(self):
        calls = []
        with mock.patch.object(hotspot, "profile_state", return_value=(True, True)), \
             mock.patch.object(hotspot, "find_ap_interface", return_value="wlan0"), \
             mock.patch.object(hotspot, "trusted_program", return_value="/usr/bin/dnsmasq"), \
             mock.patch.object(hotspot, "nmcli_ok", side_effect=lambda *a, **k: calls.append(a) or ""):
            hotspot.cmd_apply(self.store, ["band=bg"], None)
        self.assertEqual(calls[-2][:3], ("connection", "down", PROFILE_NAME))
        self.assertEqual(calls[-1][:3], ("connection", "up", PROFILE_NAME))

    def test_first_profile_gets_generated_password(self):
        calls = []
        with mock.patch.object(hotspot, "profile_state", return_value=(False, False)), \
             mock.patch.object(hotspot, "nmcli_ok", side_effect=lambda *a, **k: calls.append((a, k)) or ""):
            hotspot.write_profile(dict(DEFAULT_CONFIG), "wlan0")
        self.assertEqual(calls[0][0][:2], ("connection", "add"))
        psk = calls[1][1]["stdin_text"].splitlines()[0].split(" ", 2)[2]
        self.assertEqual(len(psk), hotspot.GENERATED_PASSWORD_LENGTH)
        validate_password(psk)

    def test_invalid_apply_changes_nothing(self):
        with mock.patch.object(hotspot, "nmcli_ok") as nm:
            with self.assertRaises(HotspotError):
                hotspot.cmd_apply(self.store, ["band=bogus"], None)
            with self.assertRaises(HotspotError):
                hotspot.cmd_apply(self.store, ["ssid=ok"], "short")
        nm.assert_not_called()
        self.assertIsNone(self.store.read_json(CONFIG_NAME))

    def test_5ghz_without_country_is_refused_before_nmcli_up(self):
        with mock.patch.object(hotspot, "trusted_program", return_value="/usr/bin/x"), \
             mock.patch.object(hotspot, "read_regdomain", return_value="00"), \
             mock.patch.object(hotspot, "nmcli_ok") as nm:
            with self.assertRaises(HotspotError) as ctx:
                hotspot.activate(dict(DEFAULT_CONFIG, band="a"), "wlan0")
        self.assertIn("country", str(ctx.exception))
        nm.assert_not_called()

    def test_5ghz_refused_when_card_marks_every_channel_no_ir(self):
        # Country set globally, but the card's own domain still blocks 5 GHz
        # (ath10k with a world-roaming EEPROM did exactly this).
        def fake_iw(*args):
            if args[:1] == ("dev",):
                return 0, "Interface wlan0\n\twiphy 0\n", ""
            return 0, PHY_NO_IR, ""
        with mock.patch.object(hotspot, "trusted_program", return_value="/usr/bin/x"), \
             mock.patch.object(hotspot, "read_regdomain", return_value="DZ"), \
             mock.patch.object(hotspot, "iw", side_effect=fake_iw), \
             mock.patch.object(hotspot, "profile_state", return_value=(True, False)), \
             mock.patch.object(hotspot, "nmcli", return_value=(0, "", "")), \
             mock.patch.object(hotspot.time, "sleep"), \
             mock.patch.object(hotspot, "nmcli_ok") as nm:
            with self.assertRaises(HotspotError) as ctx:
                hotspot.activate(dict(DEFAULT_CONFIG, band="a"), "wlan0")
        self.assertIn("firmware", str(ctx.exception))
        nm.assert_not_called()

    def test_5ghz_retries_after_rescan_before_giving_up(self):
        results = iter([(False, hotspot.CARD_5GHZ_HINT, None), (True, "", 36)])
        calls = []
        with mock.patch.object(hotspot, "trusted_program", return_value="/usr/bin/x"), \
             mock.patch.object(hotspot, "five_ghz_status", side_effect=lambda i: next(results)), \
             mock.patch.object(hotspot, "profile_state", return_value=(True, True)), \
             mock.patch.object(hotspot, "nmcli", side_effect=lambda *a, **k: calls.append(a) or (0, "", "")), \
             mock.patch.object(hotspot, "nmcli_ok", side_effect=lambda *a, **k: calls.append(a) or ""), \
             mock.patch.object(hotspot.time, "sleep"):
            hotspot.activate(dict(DEFAULT_CONFIG, band="a"), "wlan0")
        self.assertEqual(calls[0][:2], ("connection", "down"))
        self.assertEqual(calls[1][:3], ("device", "wifi", "rescan"))
        self.assertEqual(calls[-1][:2], ("connection", "up"))

    def test_5ghz_allowed_when_card_has_a_usable_channel(self):
        def fake_iw(*args):
            if args[:1] == ("dev",):
                return 0, "\twiphy 1\n", ""
            return 0, PHY_USABLE, ""
        with mock.patch.object(hotspot, "read_regdomain", return_value="US"), \
             mock.patch.object(hotspot, "iw", side_effect=fake_iw):
            self.assertEqual(hotspot.five_ghz_status("wlan0"), (True, "", 36))

    def test_5ghz_activation_pins_the_usable_channel(self):
        calls = []
        with mock.patch.object(hotspot, "trusted_program", return_value="/usr/bin/x"), \
             mock.patch.object(hotspot, "five_ghz_status", return_value=(True, "", 36)), \
             mock.patch.object(hotspot, "nmcli_ok", side_effect=lambda *a, **k: calls.append(a) or ""):
            hotspot.activate(dict(DEFAULT_CONFIG, band="a"), "wlan0")
        self.assertEqual(calls[0], ("connection", "modify", PROFILE_NAME,
                                    "802-11-wireless.channel", "36"))
        self.assertEqual(calls[1][:2], ("connection", "up"))

    def test_missing_dnsmasq_is_reported(self):
        with mock.patch.object(hotspot, "trusted_program", return_value=None), \
             mock.patch.object(hotspot, "nmcli_ok") as nm:
            with self.assertRaises(HotspotError) as ctx:
                hotspot.activate(dict(DEFAULT_CONFIG), "wlan0")
        self.assertIn("dnsmasq", str(ctx.exception))
        nm.assert_not_called()

    def test_run_locked_records_and_clears_errors(self):
        def fail():
            raise HotspotError("boom")
        with mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(hotspot.run_locked(self.store, fail), 1)
        self.assertEqual(hotspot.load_error(self.store), "boom")
        self.assertEqual(hotspot.run_locked(self.store, lambda: None), 0)
        self.assertEqual(hotspot.load_error(self.store), "")

    def test_stdin_password_reads_one_line(self):
        fake = mock.Mock()
        fake.closed = False
        fake.buffer = io.BytesIO(b"hunter22\nignored\n")
        with mock.patch.object(sys, "stdin", fake):
            self.assertEqual(hotspot.read_stdin_password(), "hunter22")
        fake.buffer = io.BytesIO(b"\n")
        with mock.patch.object(sys, "stdin", fake):
            self.assertIsNone(hotspot.read_stdin_password())


class StateDirTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "state")

    def tearDown(self):
        self.tmp.cleanup()

    def test_directory_is_private(self):
        store = StateDir(self.path)
        try:
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o700)
        finally:
            store.close()

    def test_round_trip_and_file_mode(self):
        store = StateDir(self.path)
        try:
            store.write_json(CONFIG_NAME, {"ssid": "x"})
            self.assertEqual(store.read_json(CONFIG_NAME), {"ssid": "x"})
            mode = stat.S_IMODE(os.stat(os.path.join(self.path, CONFIG_NAME)).st_mode)
            self.assertEqual(mode, 0o600)
        finally:
            store.close()

    def test_symlink_is_refused(self):
        store = StateDir(self.path)
        try:
            target = os.path.join(self.tmp.name, "elsewhere.json")
            with open(target, "w") as handle:
                handle.write('{"ssid": "evil"}')
            os.symlink(target, os.path.join(self.path, STATE_NAME))
            self.assertIsNone(store.read_json(STATE_NAME))
        finally:
            store.close()

    def test_fifo_does_not_block(self):
        store = StateDir(self.path)
        try:
            os.mkfifo(os.path.join(self.path, STATE_NAME))
            self.assertIsNone(store.read_json(STATE_NAME))
        finally:
            store.close()

    def test_symlinked_state_dir_is_refused(self):
        real = os.path.join(self.tmp.name, "real")
        os.mkdir(real, 0o700)
        os.symlink(real, self.path)
        with self.assertRaises(StateDirError):
            StateDir(self.path)


if __name__ == "__main__":
    unittest.main()
