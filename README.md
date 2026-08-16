# dnser

**Terminal-first DNS switcher for Linux.** Detects whether NetworkManager or
systemd-resolved actually controls DNS on your machine, speaks its native
protocol, and switches you to a privacy-friendly resolver — with DoT and a
one-command undo.

## Why

Most Linux DNS switchers assume one backend, ship as tray/GUI apps, or only
change the current connection so every new Wi-Fi resets you. `dnser` detects
the real DNS layer, warns about conflicting configs, and supports a **global
override** that persists across networks — the privacy use case.

## Install

```bash
git clone https://github.com/YOUR_USER/dnser
cd dnser
pipx install --editable .        # or: pip install -e ".[dev]"
```

`pipx` installs into your user PATH, but `sudo` uses root's PATH. To make
`sudo dnser` work:

```bash
sudo ln -s "$(which dnser)" /usr/local/bin/dnser
```

## Usage

```bash
dnser status                 # active backend + current DNS
dnser list                   # available provider presets
dnser backends               # which backends are usable here

sudo dnser set quad9         # switch to Quad9
sudo dnser set quad9 --dot   # ...with DNS-over-TLS (encrypted)

sudo dnser restore           # undo the last change
dnser restore --list         # show all backups
sudo dnser restore --index 2 # restore a specific backup
```

### Scopes

| Flag        | Changes                    | Persists to new networks? |
|-------------|----------------------------|---------------------------|
| *(default)* | Current connection only    | No                        |
| `--all`     | Every saved connection     | No                        |
| `--global`  | System-wide override       | **Yes**                   |

Extra flags for `set`:

- `--dot` — DNS-over-TLS with certificate verification (systemd-resolved only)
- `--no-ipv6` — skip IPv6 servers
- `--iface IFACE` — target a specific interface (default scope only)

## How it works

- **systemd-resolved** — writes `/etc/systemd/resolved.conf.d/00-dnser.conf`
- **NetworkManager** — writes connection DNS, or
  `/etc/NetworkManager/conf.d/00-dnser-global.conf` for `--global`

Every `set` snapshots the previous state first; `restore` reverts it cleanly.
`dnser status` warns if other configs on the system may also affect DNS.

## Configuration

Provider presets load from the first file found:

1. `~/.config/dnser/providers.json`
2. `/etc/dnser/providers.json`
3. Bundled default

Backups: `~/.local/state/dnser/backups/` (last 10 kept).

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
