# Deploying the relay

The relay is the only server-side piece. It holds no keys and cannot read
message content, but it does hold routing metadata (accounts, friend edges,
workspace op-logs, the offline queue), so it runs VPN-only.

Target: **cp1** (`100.64.0.3`), alongside the other services in `/srv/docker/`.

## One command

```sh
./deploy/deploy.sh
```

Builds the image on this device, ships it over SSH, installs the compose file,
creates the state directory with the right owner, and starts it. cp1 needs no
GitHub credential and no Rust toolchain -- it authenticates to nothing. Rerun to
upgrade.

Then prove it actually works, end to end, through the real deployment (after
the one-time hub-side exposure below):

```sh
ENCLAVE_RELAY_URL=wss://enclave.home.mstampfli.com \
  cargo test -p enclave-client --test deployed_relay -- --nocapture
```

That creates two accounts, builds a workspace and a channel, and round-trips a
message and a file. It is skipped when `ENCLAVE_RELAY_URL` is unset, so it never
runs in CI.

Client devices cannot test `ws://100.64.0.3:8443` directly: the headscale ACL
lets them reach cp1 on `:22` only, and the hub is the one path in. That is the
point -- the relay is reachable solely through Caddy's TLS and VPN gate.

## What the compose file guarantees

- **Tailnet-only.** Both ports publish on `100.64.0.3`, never `0.0.0.0` -- a bare
  publish would bypass cp1's `lan-firewall` too.
- **Non-root, no capabilities, read-only rootfs.** The relay runs as uid 10001
  with `cap_drop: ALL` and `no-new-privileges`; only `/data` is writable.
- **`restart: always`.** Not `unless-stopped`: a dockerd crash records containers
  as manually stopped, and `unless-stopped` then never revives them.
- **State in a bind mount** (`/srv/docker/enclave/data`), owned by uid 10001, so
  it backs up alongside the other services.

> The state directory MUST be owned by uid 10001. If it is not, the relay exits
> at startup with `state directory is not writable` rather than running fine and
> silently losing every account on the next restart. `deploy.sh` creates it
> correctly; only a hand-made directory can get this wrong.

## Hub-side exposure (one-time)

Signaling is HTTP(S), so Caddy fronts it. Media is raw UDP, so it needs a DNAT.

**1. Caddy vhost** on the hub, `/etc/caddy/Caddyfile` (`cfdns` issues the cert
over DNS-01, `access` logs requests to the journal, as on every `.home` vhost):

```caddyfile
enclave.home.mstampfli.com {
    import cfdns
    import access
    @notvpn not remote_ip 100.64.0.0/10 fd7a:115c:a1e0::/48
    handle @notvpn { abort }
    handle { reverse_proxy 100.64.0.3:8443 }
}
```

`reverse_proxy` upgrades WebSockets natively; no extra directives needed. Then:

```sh
set -a; . /etc/caddy/.env; set +a
sudo -E caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
```

**2. Split-horizon DNS** -- add to `extra_records` in
`/etc/headscale/config.yaml` so the name resolves on the tailnet, then
`sudo systemctl restart headscale`:

```yaml
- name: enclave.home.mstampfli.com
  type: A
  value: 100.64.0.1
```

**3. Media UDP.** The client derives its media address as
`<signaling host>:8444/udp`, and the signaling host resolves to the hub -- so the
hub must forward 8444/udp to cp1. Same pattern as the OVERCLOCK forward, but
tailnet-internal: add to the `*nat` block in `/etc/ufw/before.rules` (marker
`ENCLAVE-MEDIA`, keep a `.bak`):

```
-A PREROUTING -i tailscale0 -p udp --dport 8444 -j DNAT --to-destination 100.64.0.3:8444
-A POSTROUTING -d 100.64.0.3/32 -o tailscale0 -p udp --dport 8444 -j MASQUERADE
```

The MASQUERADE is not optional: without it cp1 replies straight to the client
and the client drops the packets as asymmetric.

```sh
sudo ufw route allow proto udp from any to 100.64.0.3 port 8444
sudo ufw reload
```

**4. Headscale ACL** (`/etc/headscale/acl.hujson`) -- the default is deny, and
the current `hub -> cp1` allowlist does not include these ports. Add:

- `tag:client -> tag:hub:8444` (udp) -- clients reach media via the hub
- `tag:hub -> tag:cp1:8443,8444` -- the hub reaches the relay

Validate offline before applying, or you can lock everyone out:

```sh
headscale policy check --file /etc/headscale/acl.hujson
sudo systemctl restart headscale
```

**5. Dashboard** -- `home.mstampfli.com` is maka-collector's embedded app, and
its site-health list is hardcoded in `maka-hub/main.go` (`var sites`) in the
`maka-infra` repo; add `enclave.home.mstampfli.com` there to monitor it. (The
old `sites/landing/index.html` is no longer served.)

## Verifying the exposed deployment

```sh
# signaling, through Caddy, from a tailnet device
ENCLAVE_RELAY_URL=wss://enclave.home.mstampfli.com \
  cargo test -p enclave-client --test deployed_relay -- --nocapture

# the VPN gate really refuses off-tailnet (expect a connection abort)
curl -sS --max-time 10 https://enclave.home.mstampfli.com/ ; echo "exit=$?"
```

## Backup / restore

Everything is under `/srv/docker/enclave/data`. Stop, copy, start:

```sh
ssh cp1 "cd /srv/docker/enclave && sudo docker compose stop && \
  sudo tar czf /tmp/enclave-state.tgz data && sudo docker compose start"
```

`enclave-opaque.setup` is the OPAQUE server secret: account envelopes are only
usable under the setup they were registered against, so losing it invalidates
every existing login. Back it up with the rest and never commit it.
