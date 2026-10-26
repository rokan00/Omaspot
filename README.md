# Omaspot

A bar widget for [Omarchy](https://omarchy.org) that shares your connection over Wi-Fi.
Set the network **name**, **password**, **band** (2.4 GHz / 5 GHz) and **security**
(WPA / WPA2 / WPA3), then turn it on or off with one click.

- **Left-click** the icon to open the settings panel.
- **Right-click** the icon to turn the hotspot on or off.
- The icon is dimmed while the hotspot is off. When it's on, it lights up and shows how many devices are connected.

NetworkManager does all the work. The plugin manages one connection profile called
**"Omarchy Hotspot"** (access-point mode, IPv4 shared, never auto-connects).

## Requirements

- NetworkManager (already part of Omarchy).
- **dnsmasq**, which NetworkManager uses to give connected devices an address:
  ```bash
  sudo pacman -S dnsmasq
  ```
- A Wi-Fi adapter that supports access-point mode. Check with
  `nmcli -f WIFI-PROPERTIES.AP device show <wifi-device>`.
- **For 5 GHz:** your country must be set. If it isn't, every 5 GHz channel stays "no-IR"
  (no transmitting), and the panel shows a warning. Uncomment your country in
  `/etc/conf.d/wireless-regdom` and reboot, or run `sudo iw reg set XX` for this boot only.

  Some cards also have their own firmware lock. Qualcomm `ath10k` cards such as the QCA9377
  are an example: they allow a 5 GHz channel only after hearing another 5 GHz network on it.
  The plugin reads the card's actual channel flags and pins the hotspot to a usable
  channel. If none is usable, it stops the hotspot, rescans once and checks again.
  If 5 GHz is still unavailable after that, the panel says so. Use 2.4 GHz in that case.

## Install

```bash
omarchy plugin add https://github.com/rokan00/Omaspot
```

Then add the **Hotspot** widget to your bar.

## Security options

| Option | What it uses | When to pick it |
|---|---|---|
| WPA | WPA1, TKIP | Only for very old devices. Easy to crack. |
| WPA2 *(default)* | RSN, CCMP (AES) | Works with almost every device. |
| WPA3 | SAE, protected management frames required | Strongest. Devices older than about 2019 may not be able to join. |

WEP and open (no password) networks aren't offered.

## How the password is handled

The password is stored only in the NetworkManager profile, which root owns. It travels from
the panel to the backend on **stdin**, and from the backend to `nmcli`'s connection editor
on stdin too. It never appears on a command line, so it doesn't show up in `ps` or
`/proc/*/cmdline`. Status updates sent to the bar never include it. The panel's **Show**
button fetches it only when you ask.

If you turn the hotspot on before you've set a password, a random 12-character one is
generated. Click **Show** to see it.

## Command line

```bash
python3 scripts/hotspot.py up | down | toggle | status
echo 'new-password' | python3 scripts/hotspot.py apply ssid=MyNet band=a security=wpa3
python3 scripts/hotspot.py apply band=bg </dev/null   # change settings, keep the password
omarchy-shell mlhunter.hotspot toggle | toggleHotspot | up | down
```

## Development

```bash
python3 scripts/test_hotspot.py   # stdlib unittest, nmcli is mocked
```

## License

MIT
