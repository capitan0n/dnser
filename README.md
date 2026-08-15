# dnser

**Terminal-first DNS switcher for Linux** — backend-agnostic, scriptable, with 3 change scopes.

## Why

Existing Linux DNS switchers either:

- Assume one specific backend (only NetworkManager, or only edit `/etc/resolv.conf` directly and break), or
- Ship as heavy tray/GUI apps unsuitable for terminal-first workflows, or
- Are Windows-first with token Linux support, or
- Only change the *current* connection, forcing you to reconfigure every new WiFi you join.

**dnser** detects the active DNS management layer on your system (NetworkManager today; systemd-resolved next) and speaks its native protocol. Works from a script or interactively. Supports a **global override** that also applies to future connections — the key privacy use case.

## Status

Alpha — Phase 2. Working: status/list/backends/set/restore. Roadmap below.

## Installation

Not yet released. Development install:

```bash
git clone <repo>
cd dnser
pip install -e ".[dev]"
```

## Usage

### Introspection

```bash
dnser status       # active backend + current DNS servers per interface
dnser backends     # every known backend and whether it's usable here
dnser list         # provider presets loaded from providers.json
```

### Changing DNS

```bash
# Change only the currently active connection (WiFi/Ethernet you're on):
dnser set quad9

# Change every saved connection profile at once:
dnser set cloudflare --all

# System-wide override — applies to current AND future connections.
# Best for privacy: you don't have to remember for each new network.
# Requires sudo.
sudo dnser set mullvad --global

# Target a specific interface:
dnser set cloudflare --iface wlp2s0

# Skip IPv6 servers:
dnser set quad9 --no-ipv6
```

### Restore

A snapshot is taken automatically before every `set`. To undo:

```bash
dnser restore           # revert the last change
dnser restore --list    # show all backups
dnser restore --index 2 # revert to a specific older backup
```

### Scopes explained

| Scope | Flag | What it changes | Persists to new networks? | Root? |
|---|---|---|---|---|
| current  | *(default)* | Only the active connection profile | No | No |
| all      | `--all`     | Every saved connection profile     | No | No |
| global   | `--global`  | System-wide via NM's `global-dns-domain-*` config | **Yes** | Yes |

The `--global` scope writes `/etc/NetworkManager/conf.d/00-dnser-global.conf` and reloads NM. `dnser restore` removes it cleanly.

## Configuration

Provider presets are loaded from the first existing file:

1. `~/.config/dnser/providers.json` (user override)
2. `/etc/dnser/providers.json` (system-wide)
3. Bundled default (shipped with the package)

Backup snapshots are stored in `$XDG_STATE_HOME/dnser/backups/` (default: `~/.local/state/dnser/backups/`). The last 10 are kept.

## Roadmap

- **v0.1**: NetworkManager backend, status/list/backends (done)
- **v0.2** *(current)*: set + restore with 3 scopes, snapshots
- **v0.3**: systemd-resolved backend, TUI picker (questionary)
- **v0.4**: benchmark (dnspython), DoT/DoH toggle
- **v0.5**: AUR package (PKGBUILD)

## License

GPL-3.0-or-later.
