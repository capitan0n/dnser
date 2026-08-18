# dnser

**A simple tool to configure DNS on Linux**, detects whether NetworkManager or systemd-resolved controls your DNS, applies the change through its native mechanism, and undoes it with one command.

```console
$ sudo dnser set quad9 --dot --no-llmnr
OK applied Quad9 (9.9.9.9#dns.quad9.net, ...) to system-wide global override
hardening: DoT=on, LLMNR=off
backup: 20260816T142201Z_baseline.json
```

## Why

Most Linux DNS tools assume a single backend, or only touch the active connection, so every new Wi-Fi network silently resets you. `dnser` detects the real DNS layer, warns about conflicting configuration
elsewhere on the system, and supports a **global override** that persists across
networks.

Design principle: *it does one thing.* No daemon, no TUI, no auto-apply. Every
change is explicit, inspectable with `--dry-run`, and reversible.

## Features

- **Backend-agnostic** — NetworkManager (`nmcli`) and systemd-resolved
  (`resolvectl` + drop-ins), auto-detected
- **Persistent global scope** — survives network changes, not just the current
  connection
- **DNS-over-TLS**, fail-closed and certificate-verified (systemd-resolved),
  with a pre-flight check that port 853 is actually reachable before applying
- **Fallback DNS** — a secondary resolver consulted only if the primary fails,
  set explicitly so resolved never silently falls back to its built-in servers
- **Built-in benchmarking** — `dnser check` measures cached *and* uncached
  latency for every provider, using only the Python standard library
- **Protocol hardening** — disable LLMNR and mDNS, require DNSSEC, disable the
  local resolver cache
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

### From PyPI (recommended)

```bash
pipx install dnser
```

`pipx` keeps dnser in its own isolated environment and puts the `dnser` command
on your PATH — the right choice for a system CLI, and the way to install it on
externally-managed distros (Arch, Manjaro, Debian 12+, Fedora) where a bare
`pip install` into the system Python is refused (PEP 668).

No `pipx`? Install it first:

```bash
sudo pacman -S python-pipx      # Arch / Manjaro
sudo apt install pipx           # Debian / Ubuntu
sudo dnf install pipx           # Fedora
```

### With pip

```bash
pip install dnser               # inside a virtualenv
```

On an externally-managed system, either use a virtualenv:

```bash
python -m venv .venv && source .venv/bin/activate
pip install dnser
```

or install for your user only:

```bash
pip install --user dnser
```

### From source

```bash
git clone https://github.com/capitan0n/dnser
cd dnser
pipx install --editable .        # or: pip install -e ".[dev]"
```

### Making `sudo dnser` work

`pipx` and `pip --user` install into *your* PATH, but `sudo` uses root's PATH,
so `sudo dnser` may report *command not found*. Symlink it once:

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
sudo dnser set quad9 --fallback cloudflare   # ...with a backup resolver
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

systemd-resolved has no NetworkManager-style connection profiles — DNS is configured per-link or globally — so all three scopes behave identically there. `dnser` says so explicitly when it upgrades your scope rather
than reporting something that didn't happen.

### Flags for `set`

| Flag         | Effect                                       | Backend        |
|--------------|----------------------------------------------|----------------|
| `--dot`      | DNS-over-TLS, fail-closed, cert-verified     | resolved only  |
| `--dnssec`   | Require DNSSEC validation                    | resolved only  |
| `--no-cache` | Disable the local resolver cache             | resolved only  |
| `--no-llmnr` | Disable Link-Local Multicast Name Resolution | both           |
| `--no-mdns`  | Disable Multicast DNS (`.local`)             | both           |
| `--no-ipv6`  | Skip the provider's IPv6 servers             | both           |
| `--fallback` | Secondary resolver, used only if primary fails | both         |
| `--iface IF` | Target a specific interface (default scope)  | NetworkManager |
| `--dry-run`  | Print the plan and exit                      | both           |

Flags are individual on purpose — there is no `--harden` mega-flag. You should
know exactly what you changed. Resolved-only flags fail loudly on
NetworkManager instead of silently doing less than you asked.

### Fallback DNS

`--fallback` takes a comma-separated list of provider keys and/or raw IPs, used
only when every primary server fails:

```bash
sudo dnser set quad9 --fallback cloudflare
sudo dnser set quad9 --fallback 9.9.9.10,1.1.1.1
sudo dnser set mullvad --dot --fallback quad9   # fallback is DoT too
```

- On **systemd-resolved** this writes a native `FallbackDNS=` line. dnser always
  sets it explicitly, so resolved never silently falls back to its compiled-in
  servers (Google/Cloudflare) — a surprising leak otherwise.
- On **NetworkManager**, which has no separate fallback notion, the servers are
  appended after the primaries in the same ordered list.
- Under `--dot`, a fallback given as a provider key stays certificate-verified;
  a bare IP is refused, since it can't be verified. Mixing a DoT primary with a
  plaintext fallback prints a leak warning.
- A fallback that shares servers with the primary is refused — it would never be
  consulted, so it's almost certainly a mistake.

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

Because systemd-resolved's DoT is fail-closed, `--dot` first opens a quick TCP connection to port 853 as a reachability check: if a local firewall or the ISP blocks it, dnser warns before applying.

`dnser check` sends raw DNS queries over UDP/53: one for a well-known cached
name, then randomized subdomains to force cache misses. Sockets are
connected before sending so replies from other hosts can't skew the numbers.
Providers that only answer over DoT (Mullvad) are skipped rather than reported
as broken.

## Scope and limitations

dnser manages DNS on desktop and laptop Linux systems that use
NetworkManager, systemd-resolved, or both. It does **not** cover:

- **Server / headless setups without NM or resolved** — if your DNS comes
  from hand-edited `/etc/resolv.conf`, `resolvd`, `openresolv`, Unbound,
  dnsmasq as a local forwarder, or a container's built-in resolver, dnser
  has no backend for it and will say so.
- **Immutable-root distros** (Fedora Silverblue, NixOS, GNOME OS) — the
  `/etc` overlays or read-only rootfs may block dnser's config writes even
  as root.
- **systemd-networkd without resolved** — networkd manages links but not
  resolution; dnser needs resolved on the other end.
- **Non-Linux** — see below.
- **VPN split-tunnel DNS** — dnser sets system-wide or per-connection DNS
  but does not touch VPN-specific routing. If your VPN client pushes its
  own DNS, that configuration sits in a different layer and may override or
  be overridden by dnser depending on the order of operations.

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

## Author

**capitan0n** — [github.com/capitan0n](https://github.com/capitan0n)

Issues and pull requests are welcome at
[github.com/capitan0n/dnser/issues](https://github.com/capitan0n/dnser/issues).

## License


Released under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE) for the full text.
