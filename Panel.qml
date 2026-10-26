import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

// The Hotspot popup: an on/off hero, then the network name, password, band
// and security. Edits are drafts until "Save", so flipping between options
// doesn't restart a running hotspot on every click.
//
// Like the Pomodoro panel, this holds no backend state and touches no files:
// everything it shows is read off the host widget, and every action is
// forwarded to the host's supervised command queue.
Panel {
    id: root
    moduleName: "mlhunter.hotspot"
    ipcTarget: "mlhunter.hotspot"
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null
    readonly property var barIdentity: hostWidget || root

    readonly property bool active: hostWidget ? hostWidget.active : false
    readonly property bool busy: hostWidget ? hostWidget.busy : false
    readonly property string ssid: hostWidget ? hostWidget.ssid : "Omarchy Hotspot"
    readonly property string band: hostWidget ? hostWidget.band : "bg"
    readonly property string security: hostWidget ? hostWidget.security : "wpa2"
    readonly property string iface: hostWidget ? hostWidget.iface : ""
    readonly property int clients: hostWidget ? hostWidget.clients : 0
    readonly property bool fiveGhzOk: hostWidget ? hostWidget.fiveGhzOk : false
    readonly property string fiveGhzReason: hostWidget ? hostWidget.fiveGhzReason : ""
    readonly property string errorText: hostWidget ? hostWidget.errorText : ""
    readonly property string revealedPassword: hostWidget ? hostWidget.revealedPassword : ""

    readonly property color contentForeground: bar ? bar.foreground : Color.foreground
    readonly property string contentFontFamily: bar ? bar.fontFamily : Style.font.family

    // Drafts, seeded from the live settings whenever the panel opens.
    property string draftBand: "bg"
    property string draftSecurity: "wpa2"
    property bool showPassword: false

    readonly property bool editingText: ssidField.activeFocus || passwordField.activeFocus

    readonly property bool dirty: ssidField.text !== root.ssid
        || passwordField.text !== ""
        || root.draftBand !== root.band
        || root.draftSecurity !== root.security

    readonly property string passwordProblem: {
        var value = passwordField.text
        if (value === "") return ""
        if (value.length < 8) return "At least 8 characters"
        if (value.length > 63) return "At most 63 characters"
        if (!/^[\x20-\x7e]+$/.test(value)) return "Printable ASCII only"
        if (value !== value.trim()) return "No leading or trailing spaces"
        return ""
    }

    readonly property string ssidProblem: {
        var value = ssidField.text
        if (value.length === 0) return "Name can't be empty"
        if (root.utf8Length(value) > 32) return "Name is too long (32 bytes max)"
        if (value !== value.trim()) return "No leading or trailing spaces"
        return ""
    }

    // SSIDs are limited in bytes, not characters.
    function utf8Length(text) {
        var bytes = 0
        for (var i = 0; i < text.length; i++) {
            var code = text.charCodeAt(i)
            if (code < 0x80) bytes += 1
            else if (code < 0x800) bytes += 2
            else if (code >= 0xD800 && code <= 0xDBFF) { bytes += 4; i++ }
            else bytes += 3
        }
        return bytes
    }

    readonly property bool canSave:root.dirty && !root.busy
        && root.passwordProblem === "" && root.ssidProblem === ""

    function resetDrafts() {
        ssidField.text = root.ssid
        passwordField.text = ""
        root.draftBand = root.band
        root.draftSecurity = root.security
        root.showPassword = false
        if (hostWidget) hostWidget.hidePassword()
    }

    function save() {
        if (!root.canSave || !hostWidget) return
        hostWidget.applySettings(ssidField.text, root.draftBand, root.draftSecurity, passwordField.text)
        passwordField.text = ""
        root.showPassword = false
    }

    function togglePasswordVisibility() {
        root.showPassword = !root.showPassword
        if (root.showPassword && passwordField.text === "" && hostWidget) hostWidget.revealPassword()
        if (!root.showPassword && hostWidget) hostWidget.hidePassword()
    }

    function toggleHotspot() { if (hostWidget && !root.busy) hostWidget.toggleHotspot() }

    function statusLine() {
        if (root.busy) return "Working…"
        if (root.active)
            return "On · " + root.clients + (root.clients === 1 ? " device connected" : " devices connected")
        return "Off"
    }

    function securityHint(value) {
        switch (value) {
        case "wpa": return "Legacy WPA (TKIP) is easy to crack. Use only for very old devices."
        case "wpa3": return "Strongest. Devices older than ~2019 may not be able to join."
        default: return "Works with almost every device."
        }
    }

    onOpenedChanged: if (opened) resetDrafts()

    function switchPanel(direction) {
        if (root.bar && typeof root.bar.switchPanelFrom === "function")
            return root.bar.switchPanelFrom(root.barIdentity, direction)
        return false
    }

    KeyboardPanel {
        id: panel
        anchorItem: root.anchorItem
        owner: root.barIdentity
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: panel.fittedContentWidth(Style.space(340))
        contentHeight: panel.fittedContentHeight(content.implicitHeight)

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            // Typing into the name/password fields must not toggle the hotspot.
            blocked: root.editingText
            onCloseRequested: root.close()
            onActivateRequested: root.toggleHotspot()
            onTabRequested: function(direction) { root.switchPanel(direction) }

            Column {
                id: content
                anchors.left: parent.left
                anchors.right: parent.right
                spacing: Style.spacing.panelGap

                // ---- Hero: state and the master switch.
                Item {
                    width: parent.width
                    height: Math.max(heroText.implicitHeight, powerSwitch.implicitHeight)

                    Row {
                        id: heroText
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.space(10)

                        Text {
                            textFormat: Text.PlainText
                            anchors.verticalCenter: parent.verticalCenter
                            text: "󰀂"
                            color: root.active ? Color.accent : Qt.darker(root.contentForeground, 1.6)
                            font.family: root.contentFontFamily
                            font.pixelSize: 30
                        }

                        Column {
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: Style.spacing.xs

                            Text {
                                textFormat: Text.PlainText
                                text: root.active ? root.ssid : "Hotspot"
                                color: root.contentForeground
                                font.family: root.contentFontFamily
                                font.pixelSize: Style.font.body
                                font.bold: true
                                elide: Text.ElideRight
                                width: Math.min(implicitWidth, Style.space(220))
                            }

                            Text {
                                textFormat: Text.PlainText
                                text: root.statusLine() + (root.active
                                    ? " · " + (root.band === "a" ? "5 GHz" : "2.4 GHz")
                                    : "")
                                color: Qt.darker(root.contentForeground, 1.5)
                                font.family: root.contentFontFamily
                                font.pixelSize: Style.font.bodySmall
                            }
                        }
                    }

                    ToggleSwitch {
                        id: powerSwitch
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        checked: root.active
                        busy: root.busy
                        foreground: root.contentForeground
                        accent: Color.accent
                        onToggled: root.toggleHotspot()
                    }
                }

                Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    visible: root.errorText !== "" && !root.busy
                    text: root.errorText
                    wrapMode: Text.Wrap
                    color: Color.urgent
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                }

                PanelSeparator {
                    width: parent.width
                    foreground: root.contentForeground
                }

                // ---- Name and password.
                PanelSectionHeader {
                    text: "NETWORK NAME"
                    foreground: root.contentForeground
                    fontFamily: root.contentFontFamily
                }

                TextField {
                    id: ssidField
                    width: parent.width
                    placeholderText: "Network name"
                    maximumLength: 32
                    foreground: root.contentForeground
                    accent: Color.accent
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.body
                    onAccepted: root.save()
                }

                PanelSectionHeader {
                    text: "PASSWORD"
                    foreground: root.contentForeground
                    fontFamily: root.contentFontFamily
                }

                Row {
                    width: parent.width
                    spacing: Style.spacing.controlGap

                    TextField {
                        id: passwordField
                        width: parent.width - eyeButton.width - parent.spacing
                        password: !root.showPassword
                        placeholderText: root.showPassword && root.revealedPassword !== ""
                            ? root.revealedPassword
                            : "Unchanged"
                        maximumLength: 63
                        foreground: root.contentForeground
                        accent: Color.accent
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.body
                        onAccepted: root.save()
                    }

                    Button {
                        id: eyeButton
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.showPassword ? "Hide" : "Show"
                        bordered: true
                        foreground: root.contentForeground
                        fontFamily: root.contentFontFamily
                        onClicked: root.togglePasswordVisibility()
                    }
                }

                Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    visible: root.passwordProblem !== "" || root.ssidProblem !== ""
                    text: root.ssidProblem !== "" ? root.ssidProblem : root.passwordProblem
                    color: Color.urgent
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                }

                // ---- Band.
                PanelSectionHeader {
                    text: "BAND"
                    foreground: root.contentForeground
                    fontFamily: root.contentFontFamily
                }

                ButtonGroup {
                    options: [{ "value": "bg", "label": "2.4 GHz" }, { "value": "a", "label": "5 GHz" }]
                    value: root.draftBand
                    foreground: root.contentForeground
                    accent: Color.accent
                    fontFamily: root.contentFontFamily
                    onChanged: function(v) { root.draftBand = v }
                }

                Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.Wrap
                    text: root.draftBand === "a"
                        ? (root.fiveGhzOk
                            ? "Faster, shorter range."
                            : (root.fiveGhzReason !== "" ? root.fiveGhzReason + "." : "5 GHz isn't available."))
                        : "Longer range, works with every device."
                    color: root.draftBand === "a" && !root.fiveGhzOk
                        ? Color.urgent
                        : Qt.darker(root.contentForeground, 1.7)
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                }

                // ---- Security.
                PanelSectionHeader {
                    text: "SECURITY"
                    foreground: root.contentForeground
                    fontFamily: root.contentFontFamily
                }

                ButtonGroup {
                    options: [{ "value": "wpa", "label": "WPA" },
                              { "value": "wpa2", "label": "WPA2" },
                              { "value": "wpa3", "label": "WPA3" }]
                    value: root.draftSecurity
                    foreground: root.contentForeground
                    accent: Color.accent
                    fontFamily: root.contentFontFamily
                    onChanged: function(v) { root.draftSecurity = v }
                }

                Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.Wrap
                    text: root.securityHint(root.draftSecurity)
                    color: root.draftSecurity === "wpa" ? Color.urgent : Qt.darker(root.contentForeground, 1.7)
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                }

                PanelSeparator {
                    width: parent.width
                    foreground: root.contentForeground
                }

                // ---- Save.
                Item {
                    width: parent.width
                    height: saveRow.implicitHeight

                    Text {
                        textFormat: Text.PlainText
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        text: (root.iface !== "" ? root.iface + " · " : "") + "Space toggles"
                        color: Qt.darker(root.contentForeground, 1.9)
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.caption
                    }

                    Row {
                        id: saveRow
                        anchors.right: parent.right
                        spacing: Style.spacing.controlGap

                        Button {
                            text: "Revert"
                            bordered: true
                            visible: root.dirty
                            foreground: root.contentForeground
                            fontFamily: root.contentFontFamily
                            onClicked: root.resetDrafts()
                        }

                        Button {
                            text: root.active ? "Save & restart" : "Save"
                            bordered: true
                            selected: root.canSave
                            enabled: root.canSave
                            opacity: root.canSave ? 1 : 0.45
                            foreground: root.contentForeground
                            accent: Color.accent
                            fontFamily: root.contentFontFamily
                            onClicked: root.save()
                        }
                    }
                }
            }
        }
    }
}
