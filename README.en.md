# Rednetline Cascade

A traffic forwarding script for a VPS. It works in the kernel — DNAT and
MASQUERADE in iptables, with no proxy daemons and no extra processes in the
traffic path.

```
client  ──►  [ this VPS: DNAT ]  ──►  remote server
```

## What it is for

The client connects to a nearby (or "clean") VPS, and the traffic is forwarded
to another server — the one that provides an exit in the required country. From
the client's point of view it is talking to this VPS directly: the remote
address never appears in the client configuration.

It fits WireGuard and AmneziaWG (UDP), VLESS/XRay and MTProto (TCP), and any
other TCP/UDP service — including port translation (SSH, RDP, non-standard
ports).

## Features

- **TCP and UDP**, different inbound and outbound ports.
- **Speed limited only by the link**: translation happens in the kernel, no
  user-space process sits in the traffic path.
- **Works with ufw and without it.** When ufw is active the rules are written
  into `before.rules` and loaded by ufw itself; otherwise they go straight into
  iptables and are persisted via `netfilter-persistent`.
- **Survives a reboot.** Verified on a live server: before and after a reboot
  all rules, chains, jumps and `ip_forward` match.
- **Per-tunnel traffic accounting**, both directions, in real time.
- **Result verification**: after applying, the script reads the live kernel
  rules and reports anything that is missing.
- **Lockout protection**: forwarding the server's own SSH port requires an
  explicit confirmation.
- Input validation: port `0`, port `0443` (iptables reads a leading zero as
  octal and would turn it into 291), malformed IP addresses, a loop back to the
  server's own address.

## Requirements

- Linux with iptables (tested on Ubuntu 24.04, kernel 6.8, iptables 1.8.10)
- root access
- ufw — optional; used automatically when present

## Installation

```bash
wget -O rednetline-cascade.sh \
  https://raw.githubusercontent.com/<your-repo>/main/rednetline-cascade.sh
chmod +x rednetline-cascade.sh
./rednetline-cascade.sh install
```

The script copies itself to `/usr/local/bin/rednetline` and is then available as
the `rednetline` command from any directory.

## Usage

```bash
rednetline add udp 51820 203.0.113.10          # UDP, same inbound and outbound port
rednetline add tcp 443 203.0.113.10 8443       # TCP, 443 inbound → 8443 on the remote
rednetline add tcp 2222 203.0.113.10 22 --force  # forward SSH (requires --force)
rednetline list                                # rules and traffic counters
rednetline status                              # diagnostics
rednetline delete udp 51820                    # remove a rule
rednetline flush                               # remove every rule of this project
```

Run without arguments for the interactive menu.

| Command | What it does |
|---|---|
| `add <tcp\|udp> <in_port> <IP> [out_port]` | add or replace a rule |
| `delete <tcp\|udp> <in_port>` | remove a rule |
| `list` | rules and per-tunnel traffic |
| `status` | diagnostics: backend, forwarding, ufw, chain state |
| `apply` | apply the configuration to the kernel |
| `flush` | remove every rule of this project |
| `install` / `uninstall` | install itself / remove everything |
| `menu` | interactive menu (default) |

Flags: `--force` (allow forwarding the SSH port), `--direct` (write straight
into iptables even when ufw is active), `--install-deps` (install
`iptables-persistent` without asking), `--no-bbr` (do not enable BBR).

## Client configuration

1. Add a rule on this VPS: protocol, inbound port, destination address and port.
2. In the client, replace the remote server address with **the address of this
   VPS**. The port — only if the inbound and outbound ports differ.

## How it works

### Single source of truth

All rules are stored in `/etc/rednetline-cascade/rules.conf`. On every change
the kernel state is rebuilt from that file as a whole rather than edited in
place. That is where idempotency comes from: a repeated `apply` produces exactly
the same state, and duplicates or stale rules cannot appear at all.

### Dedicated chains

Everything the script creates lives in its own chains and never mixes with
foreign rules:

| Chain | Table | Purpose |
|---|---|---|
| `RLN_PRE` | nat PREROUTING | DNAT — destination address translation |
| `RLN_POST` | nat POSTROUTING | MASQUERADE — source address translation |
| `RLN_FWD` | filter FORWARD | allows the forwarded traffic |
| `RLN_STAT` | mangle FORWARD | traffic counters |

Other rules (ufw, Docker, fail2ban) are left alone: the script inserts jumps
into its own chains instead of rewriting the system ones.

### Two backends

**With ufw active** the rules are written as three blocks into
`/etc/ufw/before.rules` and loaded by ufw itself on startup. The new file is
validated with `iptables-restore --test` before it replaces the old one, and the
previous version is kept as `before.rules.rln.bak`. This path introduces no
second rule loader, which rules out the classic "who overwrites whom" conflict
at boot.

**Without ufw** the rules are applied directly to iptables and persisted through
`netfilter-persistent`. If it is missing, the script offers to install
`iptables-persistent` (non-interactively only with `--install-deps`).

### Traffic accounting

The counters live in the `RLN_STAT` chain of the `mangle` table. That chain is
traversed by **every** packet, so the numbers are exact — unlike DNAT rule
counters, which only see the first packet of each connection (that is how the
nat table works).

## Reliability

- Input validation before anything is applied: port, IP, a loop back to the
  server's own address, and whether the port is already taken by a local
  service.
- Separate lockout protection: if the inbound port matches the SSH port of this
  server, the operation is refused unless `--force` is given.
- Post-apply verification: the script reads the live kernel rules and reports
  any discrepancy.
- Backups of every modified system file (`before.rules`, `/etc/default/ufw`).
- `flush` and `uninstall` remove **only this project's** rules — other services
  keep theirs.

## License

MIT.
