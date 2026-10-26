import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Bar icon for the Hotspot plugin, and the host for its settings popup.
// Left click toggles the popup; right click toggles the hotspot itself.
//
// This file owns the only channel to the backend. `scripts/hotspot.py watch`
// streams one schema-checked JSON line per change, and every action goes
// through one supervised, queued Process (never Quickshell.execDetached), so
// a burst of clicks can't race two `nmcli` reconfigurations. A new password
// travels to the backend on stdin, never on the command line.
BarWidget {
    id: root
    moduleName: "mlhunter.hotspot"

    property bool active: false
    property bool configured: false
    property string ssid: "Omarchy Hotspot"
    property string band: "bg"
    property string security: "wpa2"
    property string iface: ""
    property int clients: 0
    property string regdomain: ""
    property bool fiveGhzOk: false
    property string fiveGhzReason: ""
    property string errorText: ""

    // Filled only on request from the panel's eye button, and cleared again
    // when the panel closes.
    property string revealedPassword: ""

    readonly property bool busy: commandProcess.running || root.pendingCommands.length > 0

    readonly property string interpreterPath: "/usr/bin/python3"
    readonly property string scriptPath: String(Qt.resolvedUrl("scripts/hotspot.py")).replace(/^file:\/\//, "")

    readonly property int maxSnapshotBytes: 4096

    readonly property var bands: ["bg", "a"]
    readonly property var securityModes: ["wpa", "wpa2", "wpa3"]

    function backendEnvironment() {
        var env = { "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8" }
        var passthrough = ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
                           "DBUS_SYSTEM_BUS_ADDRESS"]
        for (var i = 0; i < passthrough.length; i++) {
            var value = Quickshell.env(passthrough[i])
            if (value) env[passthrough[i]] = String(value)
        }
        return env
    }

    // ---- Reading the hotspot.

    Process {
        id: watcher
        command: [root.interpreterPath, root.scriptPath, "watch"]
        clearEnvironment: true
        environment: root.backendEnvironment()
        running: true
        stdout: SplitParser {
            onRead: function(line) { root.applySnapshot(line) }
        }
        onExited: watcherRestart.restart()
    }

    Timer {
        id: watcherRestart
        interval: 2000
        repeat: false
        onTriggered: if (!watcher.running) watcher.running = true
    }

    function cleanString(value, maxLength, fallback) {
        if (typeof value !== "string" || value.length > maxLength) return fallback
        return value
    }

    function applySnapshot(line) {
        var raw = String(line || "")
        if (raw.length === 0 || raw.length > root.maxSnapshotBytes) return

        var parsed
        try {
            parsed = JSON.parse(raw)
        } catch (e) {
            return
        }
        if (!parsed || typeof parsed !== "object") return

        root.active = parsed.active === true
        root.configured = parsed.configured === true
        root.ssid = root.cleanString(parsed.ssid, 64, root.ssid)
        root.band = root.bands.indexOf(parsed.band) >= 0 ? parsed.band : root.band
        root.security = root.securityModes.indexOf(parsed.security) >= 0 ? parsed.security : root.security
        root.iface = root.cleanString(parsed.interface, 32, "")
        root.regdomain = root.cleanString(parsed.regdomain, 8, "")
        root.fiveGhzOk = parsed.five_ghz_ok === true
        root.fiveGhzReason = root.cleanString(parsed.five_ghz_reason, 300, "")
        root.errorText = root.cleanString(parsed.error, 300, "")
        var count = parsed.clients
        root.clients = (typeof count === "number" && isFinite(count) && count >= 0 && count < 1000)
            ? Math.round(count) : 0
    }

    // ---- Driving the hotspot.

    property var pendingCommands: []
    readonly property int maxPendingCommands: 8

    Process {
        id: commandProcess
        property string input: ""
        clearEnvironment: true
        environment: root.backendEnvironment()
        stdinEnabled: true
        running: false
        // Every apply gets exactly one line: the new password, or an empty
        // line for "keep the current one". The backend reads that one line.
        onStarted: {
            write(input + "\n")
            input = ""
        }
        onExited: root.drainCommands()
    }

    function runCommand(args, input) {
        if (!args || args.length === 0) return
        var queued = root.pendingCommands.slice()
        if (queued.length >= root.maxPendingCommands) return
        queued.push({ "args": args, "input": input || "" })
        root.pendingCommands = queued
        root.drainCommands()
    }

    function drainCommands() {
        if (commandProcess.running) return
        var queued = root.pendingCommands.slice()
        if (queued.length === 0) return
        var next = queued.shift()
        root.pendingCommands = queued
        commandProcess.input = next.input
        commandProcess.command = [root.interpreterPath, root.scriptPath].concat(next.args)
        commandProcess.running = true
    }

    function turnOn() { root.runCommand(["up"]) }
    function turnOff() { root.runCommand(["down"]) }
    function toggleHotspot() { root.runCommand(["toggle"]) }

    // Only known keys and values reach the command line; the backend
    // validates every one again. The password goes over stdin.
    function applySettings(ssid, band, security, password) {
        var args = ["apply"]
        var name = String(ssid || "")
        if (name.length > 0 && name.length <= 32) args.push("ssid=" + name)
        if (root.bands.indexOf(band) >= 0) args.push("band=" + band)
        if (root.securityModes.indexOf(security) >= 0) args.push("security=" + security)
        root.revealedPassword = ""
        root.runCommand(args, String(password || ""))
    }

    Process {
        id: passwordProcess
        command: [root.interpreterPath, root.scriptPath, "show-password"]
        clearEnvironment: true
        environment: root.backendEnvironment()
        running: false
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                var value = String(text || "").replace(/\n$/, "")
                root.revealedPassword = value.length <= 63 ? value : ""
            }
        }
    }

    function revealPassword() {
        if (!passwordProcess.running) passwordProcess.running = true
    }

    function hidePassword() { root.revealedPassword = "" }

    function bandLabel(value) { return value === "a" ? "5 GHz" : "2.4 GHz" }

    function securityLabel(value) {
        switch (value) {
        case "wpa": return "WPA"
        case "wpa3": return "WPA3"
        default: return "WPA2"
        }
    }

    // ---- Panel plumbing (same contract as the first-party panel widgets).

    readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

    function open() { if (panelLoader.item) panelLoader.item.open() }
    function close() { if (panelLoader.item) panelLoader.item.close() }
    function togglePanel() { if (panelLoader.item) panelLoader.item.toggle() }

    readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

    function closeForPopoutSwitch() {
        if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
    }

    function injectPanel() {
        var target = panelLoader.item
        if (!target) return
        if ("bar" in target) target.bar = root.bar
        if ("settings" in target) target.settings = root.settings
        if ("anchorItem" in target) target.anchorItem = button
        if ("hostWidget" in target) target.hostWidget = root
    }

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight

    onBarChanged: injectPanel()
    onSettingsChanged: injectPanel()

    Loader {
        id: panelLoader
        active: true
        source: Qt.resolvedUrl("Panel.qml")
        visible: false
        onLoaded: {
            root.injectPanel()
            Qt.callLater(root.injectPanel)
        }
    }

    IpcHandler {
        target: "mlhunter.hotspot"

        function open(): void { root.open() }
        function close(): void { root.close() }
        function show(): void { root.open() }
        function hide(): void { root.close() }
        function toggle(): void { root.togglePanel() }
        function up(): void { root.turnOn() }
        function down(): void { root.turnOff() }
        function toggleHotspot(): void { root.toggleHotspot() }
    }

    // Material Design Icons access-point-network (U+F0002): a theme-coloured
    // glyph like every other bar icon, dimmed while the hotspot is off.
    readonly property string glyph: "󰀂"

    WidgetButton {
        id: button
        anchors.centerIn: parent
        bar: root.bar
        text: root.active && root.clients > 0 ? root.glyph + " " + root.clients : root.glyph
        fontSize: Style.font.icon
        dimmed: !root.active
        active: root.active
        activeColor: Color.accent
        tooltipText: root.active
            ? ("Hotspot \"" + root.ssid + "\" on · " + root.clients
               + (root.clients === 1 ? " device" : " devices") + " · right-click to stop")
            : (root.errorText !== "" ? "Hotspot: " + root.errorText : "Hotspot off · right-click to start")
        onPressed: function(b) {
            if (b === Qt.RightButton) root.toggleHotspot()
            else root.togglePanel()
        }
    }
}
