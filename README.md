# dnser

**Terminal-first DNS switcher for Linux.** Detects whether NetworkManager or
systemd-resolved actually controls DNS on your machine, speaks its native
configuration language, and switches you to a privacy-friendly resolver — with
DNS-over-TLS, latency benchmarking, and a one-command undo.

```console
$ sudo dnser set quad9 --dot --no-llmnr
OK applied Quad9 (9.9.9.9#dns.quad9.net, ...) to system-wide global override
hardening: DoT=on, LLMNR=off
backup: 20260816T142201Z_baseline.json
```

## Why

Most Linux DNS switchers assume a single backend, ship as tray or GUI apps, or
only touch the active connection — so every new Wi-Fi network silently resets
you. `dnser` detects the real DNS layer, warns about conflicting configuration
elsewhere on the system, and supports a **global override** that persists across
networks.

Design principle: *it does one thing.* No daemon, no TUI, no auto-apply. Every
change is explicit, inspectable with `--dry-run`, and reversible.

## Features

- **Backend-agnostic** — NetworkManager (`nmcli`) and systemd-resolved
  (`resolvectl` + drop-ins), auto-detected
- **Persistent global scope** — survives network changes, not just the current
  connection
- **DNS-over-TLS**, fail-closed and certificate-verified (systemd-resolved)
- **Built-in benchmarking** — `dnser check` measures cached *and* uncached
  latency for every provider, using only the Python standard library
- **Protocol hardening** — disable LLMNR and mDNS, require DNSSEC
- **Snapshot before every change** — `dnser restore` reverts cleanly, and
  `dnser unset` removes dnser entirely even without a backup
- **`--dry-run`** — see the exact file contents and commands before anything runs
- **Conflict detection** — warns about other drop-ins that may override your DNS
- **15 provider presets** (Quad9, Mullvad, AdGuard, Cloudflare, OpenDNS, Google),
  fully overridable via JSON

## Requirements

- Linux with **NetworkManager** or **systemd-resolved**
- Python 3.10+
- `root` for anything that changes system state

## Install

### From PyPI

```bash
pipx install dnser
```

### From source

```bash
git clone https://github.com/capitan0n/dnser
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
dnser status                 # active backend, current DNS, protocol state
dnser list                   # available provider presets
dnser check                  # benchmark all providers (cached + uncached)
dnser backends               # which backends are usable on this system

sudo dnser set quad9         # switch to Quad9
sudo dnser set quad9 --dot   # ...over DNS-over-TLS
dnser set quad9 --dry-run    # show what would happen, change nothing

sudo dnser unset             # remove dnser's config, back to system defaults
sudo dnser restore           # undo the last change
dnser restore --list         # show all backups
sudo dnser restore --index 2 # restore a specific backup
```

### Scopes

| Flag        | Changes                 | Persists to new networks? |
|-------------|-------------------------|---------------------------|
| *(default)* | Current connection only | No                        |
| `--all`     | Every saved connection  | No                        |
| `--global`  | System-wide override    | **Yes**                   |

systemd-resolved has no per-connection concept, so all three scopes behave
identically there. `dnser` says so explicitly when it upgrades your scope rather
than reporting something that didn't happen.

### Flags for `set`

| Flag         | Effect                                       | Backend        |
|--------------|----------------------------------------------|----------------|
| `--dot`      | DNS-over-TLS, fail-closed, cert-verified     | resolved only  |
| `--dnssec`   | Require DNSSEC validation                    | resolved only  |
| `--no-llmnr` | Disable Link-Local Multicast Name Resolution | both           |
| `--no-mdns`  | Disable Multicast DNS (`.local`)             | both           |
| `--no-ipv6`  | Skip the provider's IPv6 servers             | both           |
| `--iface IF` | Target a specific interface (default scope)  | NetworkManager |
| `--dry-run`  | Print the plan and exit                      | both           |

Flags are individual on purpose — there is no `--harden` mega-flag. You should
know exactly what you changed. Resolved-only flags fail loudly on
NetworkManager instead of silently doing less than you asked.

## How it works

- **systemd-resolved** — writes `/etc/systemd/resolved.conf.d/00-dnser.conf`,
  then restarts the service
- **NetworkManager** — sets `ipv4.dns`/`ipv6.dns` on connection profiles
  (addressed by UUID, since profile names are neither unique nor
  unambiguous), or writes `/etc/NetworkManager/conf.d/00-dnser-global.conf`
  for `--global`

Files under `/etc` are written atomically, so an interrupted run can never leave
a truncated DNS config behind. Every `set` and `unset` snapshots the previous
state first, and `dnser status` scans for other drop-ins that could influence
resolution independently of dnser.

`dnser check` sends raw DNS queries over UDP/53: one for a well-known cached
name, then randomized subdomains to force authoritative lookups. Sockets are
connected before sending so replies from other hosts can't skew the numbers.
Providers that only answer over DoT (Mullvad) are skipped rather than reported
as broken.

## Configuration

Provider presets load from the first file found:

1. `~/.config/dnser/providers.json`
2. `/etc/dnser/providers.json`
3. The copy bundled with the package

Backups live in `~/.local/state/dnser/backups/` (last 10 kept), honouring
`XDG_STATE_HOME`. Under `sudo` they are written to the invoking user's home, not
`/root`, so `dnser restore` works without root when it doesn't need it.

## Contributing

Issues and pull requests are welcome. Please keep changes minimal and in the
spirit of the tool: one obvious behaviour per flag, no hidden magic, and no new
runtime dependencies without a strong reason.

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

## License

<!-- TODO: add the LICENSE file before the first release -->

Released under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE) for the full text.
