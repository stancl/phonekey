# phonekey

> [!CAUTION]
> This code was almost entirely written by an LLM (Claude), and reviewed by
> another LLM pass, not by a human security reviewer. Before trusting it with
> keys that matter, read the parts that decide whether the key can leak and what
> gets signed, under 1,000 lines:
>
> 1. **`web/app.js`:** `keyFromPRF`, `unlock`, `approval`, `signable`,
>    `signRequest`, `approve`, the grant functions (`startGrant`, `endGrant`,
>    `runGrant`), and how request details are rendered (`h`, `renderDetails`,
>    `renderContext`).
> 2. **`web/ed25519.js` and `web/sshsig.js`:** key derivation, signing, and
>    the SSH wire encoding.
> 3. **The top of `internal/server/server.go`:**
>    - the routes, static file serving and the CSP
>    - the `sameOrigin` and `session` wrappers, and `checkApproval`
>    - `createRequest`, `submitSignature`, `pair` and `removeKey`
>
> If you deploy with the NixOS module, also check the `sandbox` settings in
> `flake.nix`.

Approve SSH logins and commit signatures with a passkey, on your phone or in a
desktop browser.

An ssh-agent on the dev box passes every signing request to a small backend,
`phonekeyd`. The backend sends a push notification to its web app. You see what's
being signed, approve with Face ID, and the page derives an ordinary
`ssh-ed25519` key from the passkey, signs in the browser and forgets the key. No
private key is stored anywhere: not on the dev box, not on the backend, not in a
vault.

- [Setting up](#setting-up)
- [Using it](#using-it)
- [How it works](#how-it-works)
- [Threat model](#threat-model)
- [Dependencies](#dependencies)
- [Development](#development)
- [Open questions and future work](#open-questions-and-future-work)

## Setting up

For a NixOS host on a tailnet with an iPhone, [QUICKSTART.md](QUICKSTART.md)
walks through the whole setup. The rest of this section covers the general
case.

You need four things: the backend running somewhere your phone can reach over
HTTPS, a passkey paired with it, the agent on each dev box, and git/jj/ssh
pointed at the agent.

### 1. Run the backend

The backend should run on a host other than the dev boxes, or at least under a
separate account: whoever controls it controls the page that handles your key
(see [Threat model](#threat-model)). It needs a writable directory for its
SQLite database.

The phone needs a real HTTPS hostname. phonekey gets one from your tailnet, so
nothing is exposed to the internet. Pick one of two modes:

| | **Own tailnet machine** (built in) | **The host's Tailscale** (`tailscale serve`) |
| --- | --- | --- |
| URL | `https://phonekey.<tailnet>.ts.net` | `https://<host>.<tailnet>.ts.net[:port]` |
| Needs | nothing on the host; an auth key or one approval | root, or a Tailscale operator account, to configure `tailscale serve` |
| Listens on the host | nothing: no TCP port, not even on 127.0.0.1 | a Unix socket only phonekeyd's account and group can open (or a TCP address), which the host's tailscaled proxies to |
| Who terminates TLS | phonekeyd itself (`tsnet`, the tailnet's certificate) | the host's tailscaled |
| Hostname | its own, so it can move to another host | the host's |

Both need MagicDNS and HTTPS certificates enabled for the tailnet (admin console
→ DNS).

#### Own tailnet machine

phonekeyd joins the tailnet as its own machine through Tailscale's `tsnet`
library, and serves HTTPS only there.

```sh
phonekeyd --db ~/phonekey/phonekey.db serve \
  --tailscale-hostname phonekey --vapid-subject you@example.com
```

- **First login.** It uses an auth key (`--tailscale-authkey-file`, or
  `$TS_AUTHKEY`). Without one, phonekeyd logs a login URL and waits for you to
  approve the machine. The node state is kept in `tailscale/` next to the
  database, so later starts don't need either.
- **Auth key.** Prefer a single-use, tagged auth key (e.g. `tag:phonekey`),
  and a tailnet ACL that lets your devices reach that tag but gives the tag
  itself no outbound access. The phonekey machine is a full tailnet member, and
  its traffic runs inside phonekeyd, out of reach of host firewalls or systemd.
  A single-use key can't add further machines if it leaks.
- **Key expiry.** Tagged machines don't expire. Otherwise, disable key expiry
  for the machine in the admin console, or it drops off the tailnet when its
  node key expires.
- **No local listener.** There's no plain listener unless you add
  `--addr 127.0.0.1:8080`. Agents, including one on the same host, use the
  `https://phonekey.<tailnet>.ts.net` URL. That needs their host on the tailnet
  itself.
- **Admin commands** use the same database:
  `phonekeyd --db ~/phonekey/phonekey.db pair-code`.

#### The host's Tailscale

phonekeyd serves plain HTTP, and the host's tailscaled terminates TLS in front of
it. Listen on a Unix socket, so other accounts on the host can't reach
phonekeyd. The socket is created for phonekeyd's own account and group; root's
tailscaled can always open it.

```sh
phonekeyd --db ~/phonekey/phonekey.db serve --addr unix:$XDG_RUNTIME_DIR/phonekey.sock \
  --vapid-subject you@example.com
sudo tailscale serve --bg --https=8443 unix:$XDG_RUNTIME_DIR/phonekey.sock   # undo: sudo tailscale serve --https=8443 off
```

- **Plain TCP.** `--addr host:port` works as well, and without `--addr` phonekeyd
  listens on `127.0.0.1:8080`. Every account on the host can reach a TCP
  listener. That doesn't bypass anything (the web API needs a session, the dev
  box API a token), but it's more exposed than a socket.
- **Port.** Any port works; 443 gives the shortest URL, if it's free on that
  host.

#### NixOS

The flake's module runs one instance per person. They aren't tied to Linux users
on the box; each is a hardened system service under its own account
`phonekeyd-<name>`, with its state in `/var/lib/phonekeyd/<name>`. Other
services and accounts on the box, and the other instances, can't read its
state or reach it.

```nix
# flake inputs: phonekey.url = "github:stancl/phonekey";
modules = [
  phonekey.nixosModules.phonekeyd   # or .default, with the dev box module too
  {
    services.tailscale.enable = true;  # for serve.httpsPort
    services.phonekeyd.instances = {
      # The host's Tailscale: https://<host>.<tailnet>.ts.net:8443, proxied to
      # /run/phonekeyd-samuel/http.sock.
      samuel = {
        vapidSubject = "samuel@example.com";
        serve.httpsPort = 8443;
      };
      # Its own tailnet machine: https://phonekey-alice.<tailnet>.ts.net, nothing
      # listening on the host.
      alice = {
        vapidSubject = "alice@example.com";
        tailscale.hostname = "phonekey-alice";
        tailscale.authKeyFile = "/run/secrets/alice-ts-authkey";  # optional; otherwise journalctl -u phonekeyd-alice
      };
    };
  }
];
```

- **Default listener.** Without `tailscale.hostname`, an instance listens on
  `/run/phonekeyd-<name>/http.sock`. `serve.httpsPort` publishes that socket
  through the host's `tailscale serve`; you can also run `tailscale serve`
  yourself.
- **Public site.** To serve an instance publicly through nginx instead, proxy to
  that socket and let nginx join the instance's group:
  ```nix
  users.users.nginx.extraGroups = [ "phonekeyd-samuel" ];
  services.nginx.virtualHosts."phonekey.example.com".locations."/".proxyPass =
    "http://unix:/run/phonekeyd-samuel/http.sock:";
  ```
  An event stream runs through that proxy, so turn off response buffering for
  `/api/web/events`. phonekeyd sends `X-Accel-Buffering: no`, which nginx
  honours by default.
- **Other listeners.** `address` sets a different listener (`host:port` or
  `unix:/path`).
- **One instance per hostname.** At most one instance may use `serve.httpsPort`
  (the host's own hostname), and nothing else should be served on that
  hostname, on any port. Browsers treat all ports of a hostname as one site:
  services there would receive the instance's session cookie, and their pages
  could ask for its passkey. Give further instances `tailscale.hostname`.
- **Admin commands** run as root, with the instance name first:
  `phonekeyd-ctl samuel pair-code`, `phonekeyd-ctl samuel devbox add mybox`,
  `phonekeyd-ctl samuel keys`. They run in the instance's sandbox, as its
  account, without network.
- **Sandbox.** The goal is that a compromised phonekeyd (a bug, or a malicious
  dependency) can't reach beyond its own instance: not other services, other
  instances or accounts on the host. Each instance:
  - runs as its own account with its own user namespace and no capabilities
  - can only write its own state directory, and can't see other accounts'
    processes
  - runs under a syscall filter, with no access to the host's tailscaled or
    D-Bus sockets or `/dev/shm`, and can only execute programs from the Nix
    store
  - has limits on memory, tasks, CPU (one core) and IO priority
  - can't bind host ports, except tsnet's UDP socket or a TCP `address`
  - can't reach localhost, link-local, private or tailnet addresses, except
    DNS resolvers (systemd-resolved, MagicDNS over IPv4 and IPv6,
    `networking.nameservers`). If
    your resolver comes from DHCP on a private network, add it to
    `ipAddressAllow`. With a TCP `address`, this network restriction is left
    out so connections can come in. In the built-in tailnet mode it doesn't
    cover traffic inside the tailnet, which runs in phonekeyd; that takes the
    ACL described under [Auth key](#own-tailnet-machine).

  `systemd-analyze security` rates each instance 1.1 ("OK").

#### Either way

- **Pick the hostname once.** The passkey, and so the derived SSH key, is bound
  to the page's hostname. A different hostname later means a new passkey and new
  keys on GitHub.
  - In the built-in mode the name stays the same wherever the backend runs, as
    long as the node state moves along.
  - With the host's Tailscale, the hostname is the host's.
- **VAPID subject.** Push services need a contact: an email address or an
  `https:` URL (the backend's own URL works). Apple's push service rejects some
  placeholders.

### 2. Pair a passkey

Works on the iPhone as a home-screen app, with passkeys in iCloud Keychain or
1Password, and in desktop browsers whose passkey provider supports the PRF
extension.

On the backend host, get a one-time code (valid 10 minutes):

```sh
phonekeyd --db … pair-code        # NixOS: sudo phonekeyd-ctl <instance> pair-code
```

**iPhone.** Use iCloud Keychain as the passkey provider. It approves with just
Face ID, and a 1Password-held passkey adds 1Password's own unlock.
1. Open `https://phonekey.<tailnet>.ts.net` in Safari, then Share → **Add to
   Home Screen**.
2. Open phonekey from the home screen. Push only works inside the installed
   app, which has its own storage separate from Safari.
3. Enter the code and tap **Create passkey**. If the provider doesn't support
   PRF, the page says so. If you already have a passkey for this hostname (e.g.
   after moving the backend to another host), tap **Use an existing passkey**
   instead: it derives the same key as before.
   - **If iOS offers 1Password instead of iCloud Keychain:** iOS offers
     whichever provider is set as the default. Pick *Passwords* via the sheet's
     other options, or switch 1Password off for that moment under Settings →
     General → AutoFill & Passwords.
4. Under **Notifications, grants and keys**, tap **Enable notifications**, then
   **Send test**.

**Desktop browser.** Open the same URL, or a forwarded
`http://localhost:<port>`, which browsers treat as secure. Pair the same way.
Notifications work from a normal tab. On macOS they also have to be allowed for
the browser in System Settings → Notifications.

**Another device.** If your passkey syncs (e.g. iCloud Keychain to your Mac),
tap **Log in with passkey** there instead of pairing again: the same passkey
derives the same key. A passkey from another provider derives a different key.
Add it with **Add another passkey** while logged in.

After pairing, the page shows the `ssh-ed25519 …` key. Add it on GitHub twice,
as an **Authentication key** and as a **Signing key**.

### 3. Run the agent on each dev box

On the backend host, register the dev box and copy the token it prints. The
backend stores only a hash, so the token can't be shown again.

```sh
phonekeyd --db … devbox add mybox > mybox.token     # NixOS: sudo phonekeyd-ctl <instance> devbox add mybox
```

On the dev box:

```sh
phonekey-agent --backend https://phonekey.<tailnet>.ts.net --token-file ~/.config/phonekey/token \
  [--socket $XDG_RUNTIME_DIR/phonekey-agent.sock] \
  [--upstream /run/user/1000/op-agent.sock]
```

- **`--upstream`** also offers another agent's keys, e.g. a forwarded 1Password
  agent. Signing requests for those keys go to that agent unchanged.
- **The phone key** comes from the backend, which hands it to registered dev
  boxes. `--keys FILE` pins it instead.
- **Export the public key** once, to point tools at. The agent lists the
  phone keys with the comment `phonekey`, before any upstream keys:
  ```sh
  SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/phonekey-agent.sock ssh-add -L | grep ' phonekey$' > ~/.ssh/phonekey.pub
  ```
  With several passkeys registered, keep the line whose fingerprint
  (`ssh-keygen -lf`) matches the one the page shows.

On NixOS, `phonekey.nixosModules.phonekey-agent` sets this up per user:
`programs.phonekey-agent.users.<name> = { backend = …; upstream = …; }` gives
that user:
- the agent as a systemd user service
- the binaries and a `phonekey-use` switching helper
- ssh using the agent for chosen hosts (`ssh.hosts`, default `github.com`)

The token goes in `~/.config/phonekey/token`. The service is skipped while it's
missing, so start it once it's there (`systemctl --user start phonekey-agent`);
later logins start it by themselves.
[QUICKSTART.md](QUICKSTART.md) shows it in full.

On macOS with nix-darwin, `phonekey.darwinModules.phonekey-agent` takes the
same options, with a launchd agent for the systemd user service. It runs for
the listed users once the token is there, waiting for it until then, and logs
to `~/Library/Logs/phonekey-agent.log`. macOS has no `XDG_RUNTIME_DIR`, so the
socket is `~/.ssh/phonekey-agent.sock`, where `ssh.hosts` point too.
phonekey-keygen doesn't look there by itself: set `PHONEKEY_SOCKET` to it, or
`SSH_AUTH_SOCK`, for git and jj to sign through the agent.

Elsewhere, a systemd user unit is enough (no root needed). For example,
`~/.config/systemd/user/phonekey-agent.service`:

```ini
[Service]
ExecStart=%h/bin/phonekey-agent --backend https://phonekey.<tailnet>.ts.net --token-file %h/.config/phonekey/token
Restart=on-failure

[Install]
WantedBy=default.target
```

### 4. Point git, jj and ssh at it

**How the pieces fit.**
- **Logging in and signing both ask an agent.** ssh, logging in to a server,
  and `ssh-keygen`, which git and jj run to sign commits, both ask an
  ssh-agent to sign with a given public key.
- **The key file picks the key.** Configure that key as a symlink,
  `~/.ssh/active.pub`, and switching keys is one command.
- **phonekey-agent picks who approves**, by the key it's asked to sign with:
  - a key registered on your phonekeyd goes to the phone
  - any other key goes to its `--upstream` agent, e.g. a forwarded 1Password
    agent

All that's left is getting the tools to talk to phonekey-agent. Pick one:

- **Set `SSH_AUTH_SOCK` to it.** That's the simplest: ssh, git and jj all use
  it, for every key and every host.
  ```sh
  export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/phonekey-agent.sock      # bash
  $env.SSH_AUTH_SOCK = $"($env.XDG_RUNTIME_DIR)/phonekey-agent.sock"  # nushell
  ```
- **Leave `SSH_AUTH_SOCK` alone,** e.g. because it points at another agent, or
  because you can't set it per user (the NixOS module can't):
  - **ssh:** `IdentityAgent $XDG_RUNTIME_DIR/phonekey-agent.sock` in
    `~/.ssh/config`, for the hosts that should use it. The NixOS module adds
    this for the hosts in `ssh.hosts`.
  - **git and jj:** sign through `phonekey-keygen` (below).

`phonekey-keygen` stands in for `ssh-keygen`, which git and jj can be told to
run instead. It runs the real `ssh-keygen` after doing two things:
1. **It points `ssh-keygen` at phonekey-agent,** by setting `SSH_AUTH_SOCK`
   for that one command. That's only needed if you leave `SSH_AUTH_SOCK` alone.
2. **For jj, it turns stdin into a file.** jj passes the commit to
   `ssh-keygen` on stdin, so the agent can't read it. The shim writes it to a
   temporary file and passes that instead, as git does, so the phone can show
   the commit's subject, author and change id. That's useful either way.

Signatures are the same with or without it.

Point the tools at a symlink rather than at the key itself, so that switching
keys later (see below) is one command:

```sh
ln -sfn ~/.ssh/phonekey.pub ~/.ssh/active.pub
```

**git**

```ini
[gpg]
	format = ssh
[gpg "ssh"]
	program = phonekey-keygen   # only needed if SSH_AUTH_SOCK isn't phonekey-agent
[user]
	signingkey = ~/.ssh/active.pub
```

**jj.** Sign when pushing, so one approval covers the push:

```toml
[signing]
behavior = "drop"                # don't sign on every rewrite...
backend = "ssh"
key = "~/.ssh/active.pub"

[signing.backends.ssh]
program = "phonekey-keygen"      # lets the phone show jj's commits

[revsets]
git-sign-on-push = "~signed() & mine()"   # ...sign the pushed commits instead
```

To sign deliberately instead, drop the `[revsets]` part and run
`jj sign -r a..d` before pushing. That's one command, so one approval with
*Approve + rest*.

**ssh**

```
Host github.com
  IdentityFile ~/.ssh/active_auth.pub
  IdentitiesOnly yes
```

`active_auth.pub` is a second link, for logins (`ln -sfn ~/.ssh/phonekey.pub
~/.ssh/active_auth.pub`). With one key for both, it points at the same file as
`active.pub`. A second link lets 1Password keep separate signing and login
keys, so its prompt tells you which kind of request it is.

**Switching between 1Password and the phone.** With `--upstream`, one agent
offers both kinds of key, and the links decide which is used. With the NixOS
module, `phonekey-use desktop` / `phonekey-use phone` switches both links
between named keys (`identities`: one key, or a `sign`/`auth` pair), and
`phonekey-use FILE` points both at one key file. By hand:

```sh
# at the desk: 1Password approves
ln -sfn ~/.ssh/op-github.pub      ~/.ssh/active.pub
ln -sfn ~/.ssh/op-github_auth.pub ~/.ssh/active_auth.pub
# away: phonekey approves on the phone
ln -sfn ~/.ssh/phonekey.pub ~/.ssh/active.pub
ln -sfn ~/.ssh/phonekey.pub ~/.ssh/active_auth.pub
```

- **The upstream socket.** A forwarded 1Password agent's socket only exists
  while you're connected with agent forwarding. Without it, phonekey-agent
  offers just the phone keys, and signing with `op-github.pub` fails until you
  switch back.
- **Scope.** The symlink is global to the machine. For per-shell switching, git
  can take `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0`, and ssh
  expands environment variables in `IdentityFile`. jj has no per-key
  environment override; it needs a separate `JJ_CONFIG` or `--config`.

## Using it

- **Approving.** Each signature shows up as a card, with a notification. The
  card shows what the signed bytes say (SSH login: user, server key; or a file
  signature: namespace, hash). It also shows what the dev box says: the
  command, the server name, the commit's subject, author, body and jj change
  id. **Approve** asks for the passkey and signs. **Deny** fails the command on
  the dev box.
- **Approve + rest of "\<command\>".** Use this when one command signs several
  times: `jj sign -r a..d`, `jj git push` with sign-on-push (each commit, then
  the login), `git rebase -S`. The page keeps the key in memory and signs that
  command's next requests by itself, listing each one in the banner. It stops
  when:
  - the window ends (30 s by default, *Grant length* setting, capped by the
    server's `--max-grant`)
  - the page is hidden
  - you tap **End**

  It isn't offered for an `ssh` or `ssh-keygen` started on its own, which signs
  only once. It's not offered for a request that came through a forwarded agent
  either: those are marked *Forwarded* and always ask.
- **Separate commands ask separately.** Three `git commit -S` runs in a row are
  three approvals, because each is its own process. Commits made by jj and
  signed when you push need one approval per push.
- **Expiry.** A request expires after 90 s (`phonekey-agent --deadline`), and
  the command then fails. Ctrl-C on the dev box withdraws it.
- **Recent** lists the last signatures: who approved each (you or a grant), the
  command, the dev box, and the full card details.
- **Keys** (under *Notifications, grants and keys*) lists every registered key,
  marks the one this device is logged in with, and counts its logins and
  devices with notifications.
  - **Remove** revokes a key: its logins end, so those devices are logged out
    and stop getting notifications, and its pending requests are denied.
  - Removing a key, or adding one without a pairing code, asks for a
    registered passkey first. A session alone can't change the keys.
  - Removing the key you're logged in with logs you out on this device, so to
    clean up several keys, log in with the one you keep first.
  - The last key can't be removed.
  - The passkey itself stays in your password manager, and the key on GitHub
    if you added it there; remove those separately.
  - `phonekeyd keys rm` does the same from the command line.
- **Logins per command.** `jj git clone` logs in twice, so it asks twice
  unless you use *Approve + rest*.
- **Agent log.** A refused signature shows up twice in the agent's log: once
  from phonekey-agent, once as `agent 13: …` from Go's ssh-agent library.
- **Diagnostics** checks PRF and Ed25519 support, derives and shows the key
  (should match on every device), and signs a test message. It prints a
  snippet that verifies the signature with `ssh-keygen -Y verify`.

## How it works

```
 git / jj / ssh ──SSH_AUTH_SOCK──▶ phonekey-agent ──HTTPS + token──▶ phonekeyd ──Web Push──▶ phone
        ▲                          (dev box)        (long-poll)      (queue, page)              │
        └──────── signature ◀──────────┘ ◀──────── signature ◀──────── page signs ◀── passkey PRF
```

### The key

1. **PRF.** The page calls WebAuthn with the PRF extension and a fixed salt
   (`phonekey/ssh-ed25519/v1`). After user verification, the authenticator
   returns 32 bytes: an HMAC keyed by a secret that belongs to the passkey. The
   same passkey and salt always give the same bytes, and only pages on the
   passkey's domain can ask.
2. **Seed.** HKDF-SHA-256 with info `phonekey ssh-ed25519 seed v1` turns them
   into an ed25519 seed. `web/ed25519.js deriveSeed` does this, and
   `internal/keyderive` is a Go mirror used by tests and the simulator. A test
   pins both to the same output.
3. **Signing.** The page imports the seed into WebCrypto Ed25519, or into the
   vendored `noble-ed25519` when WebCrypto fails the RFC 8032 test vectors.
   Every WebCrypto signature is also checked with noble and redone with noble
   if it's wrong. Then the page signs and drops the key and the PRF output.
4. **Unused passkey parts.** The passkey's own WebAuthn key pair is never used,
   and assertions aren't verified. Only PRF matters.
5. **Rotation.** Changing the salt (`phonekeyd serve --salt`) gives a new,
   independent key from the same passkey.

### Request flow

1. ssh/git/jj ask the agent to sign `data` with the phone key. That's an SSH
   userauth payload, or the SSHSIG blob `ssh-keygen -Y sign` builds.
2. The agent works out context, then `POST /api/devbox/requests` with the key,
   the data, the context and its deadline.
3. phonekeyd parses the data (`internal/sshwire`) and refuses anything that's
   neither userauth nor SSHSIG. It stores the request as `pending`, wakes the
   page's event stream and sends a push.
4. The page shows the request. On approval it signs `data` and posts the
   signature. phonekeyd checks the signature against the registered key and
   marks the request `signed`.
5. The agent's long-poll (`GET /api/devbox/requests/{id}?wait=25`) returns the
   signature, and the agent hands it to the client as a normal `ssh-ed25519`
   signature.

Requests end as `signed`, `denied`, `expired` (past the deadline) or
`cancelled` (the client disconnected). A sweeper expires overdue requests and
deletes resolved ones after `--retention` (7 days).

### Code map

| Path | Responsibility |
| --- | --- |
| `cmd/phonekeyd` | CLI: `serve` (including the tailnet listener), `pair-code`, `devbox add/list/rm`, `keys` |
| `internal/server/server.go` | HTTP API, CSP and security headers, sessions, the event stream (SSE), long-polls, the push hold-back |
| `internal/server/push.go` | VAPID keys (generated on first start and kept in the database), Web Push delivery, dropping dead subscriptions |
| `internal/server/summary.go` | the one-line summary used for notifications and card titles |
| `internal/store` | SQLite (`modernc.org/sqlite`, no cgo): keys, dev boxes, pairing codes, nonces, sessions, push subscriptions, requests |
| `internal/sshwire` | parsing userauth payloads, SSHSIG blobs and `session-bind@openssh.com` |
| `internal/protocol` | JSON types shared by the backend, the agent and the simulator |
| `cmd/phonekey-agent`, `internal/agent/agent.go` | the ssh-agent: per-connection state, upstream proxying, deadline, cancel on disconnect, session-bind policy |
| `internal/agent/context.go`, `proc_linux.go` | finding the requesting process (`SO_PEERCRED`, `/proc`), the scope, ssh destination and git action, reading git's commit file |
| `internal/agent/knownhosts.go` | naming the server from known_hosts, including hashed entries |
| `internal/agent/client.go` | the dev box API client |
| `cmd/phonekey-keygen` | the jj shim; also points git and jj at the agent's socket without `SSH_AUTH_SOCK` |
| `web/app.js` | the page: pairing, login, approvals, grants, push, Recent, diagnostics |
| `web/ed25519.js`, `web/sshsig.js` | key derivation and signing; SSH wire encoding and SSHSIG armor |
| `web/sw.js` | the service worker: shows a notification for every push, opens the request on click |
| `web/vendor/noble-ed25519.js` | `@noble/ed25519` 3.2.0, unmodified (integrity hash in `web/vendor/README.md`) |
| `internal/sim`, `cmd/phonekey-sim` | a fake approver for tests and manual testing (see [Development](#development)) |
| `e2e/` | end-to-end tests (see [Development](#development)) |
| `flake.nix` | the devshell; packages `phonekeyd` (server) and `phonekey-agent` (agent and jj shim), `default` with both; NixOS modules `phonekeyd` (`services.phonekeyd.instances`) and `phonekey-agent` (`programs.phonekey-agent.users`), `default` with both |

### Backend API

- **Dev box API**, authenticated with `Authorization: Bearer <token>`:
  - `POST /api/devbox/requests`
  - `GET /api/devbox/requests/{id}?wait=N`
  - `DELETE /api/devbox/requests/{id}`
  - `GET /api/devbox/keys` (the registered keys, in authorized_keys format)

  Each dev box has its own token. The backend stores only a hash of it. A dev
  box can only poll or cancel its own requests.
- **Web API**, authenticated with a session cookie:
  - `config`
  - `nonce`, `login`, `pair`, `logout`
  - `requests`, `history`, `events` (SSE)
  - `requests/{id}/signature`, `requests/{id}/deny`
  - `keys/{id}` (DELETE)
  - `push/subscribe`, `push/test`

  All paths are under `/api/web/`.
- **Logging in.** The page asks for a nonce and signs `phonekey-auth-v1\n<nonce>`
  with the derived key. phonekeyd checks the signature against a registered key
  and sets a 30-day `HttpOnly`, `SameSite=Strict` cookie. Listing requests
  therefore needs no Face ID; signing always does.
- **Pairing** registers a new key. It needs a one-time code from `pair-code`, or
  an existing session plus an *approval*: a registered key's signature over a
  fresh nonce. Removing a key needs an approval too. A session cookie on its
  own can read and deny requests, but can't change the registered keys.
- **One user, many keys.** Any registered key can log in and sees everything.
  Each web session, and each push subscription made from it, belongs to the
  key that logged in. The page re-sends its existing subscription after each
  login, so a device that switched passkeys isn't cut off when the old key is
  removed. A subscription made for another backend's VAPID key (an earlier
  backend under the same hostname) is replaced instead, when you enable
  notifications. Removing a key deletes its sessions and subscriptions (foreign
  keys) and denies its pending requests.
- **Cross-site requests.** State-changing web calls must come from the same
  origin: `Sec-Fetch-Site: same-origin`, or a matching `Origin` header.
- **Content security policy.** The page has a strict CSP: `script-src 'self'`,
  no inline code, nothing from other origins.
- **Push hold-back.** When a request comes from a command that had a signature
  approved within `--max-grant`, its push waits 2 s. It's dropped if a grant
  signed the request meanwhile, so auto-signed requests don't each notify.

### Agent

- **Settings** come from flags or `PHONEKEY_*` environment variables
  (`PHONEKEY_BACKEND`, `PHONEKEY_TOKEN_FILE`, `PHONEKEY_UPSTREAM`, …). Paths
  may contain `$HOME` or `$XDG_RUNTIME_DIR`, which the agent expands. That's
  how the NixOS module's per-user settings file works.
- **Per-connection state.** Each client connection gets its own state. That
  holds the session bindings and an upstream connection, if any.
- **Cancel on disconnect.** `x/crypto/ssh/agent.ServeAgent` doesn't read from
  the socket while a request is being handled. The agent reads the socket
  itself through a pipe, so a client that disconnects (Ctrl-C) cancels the
  backend request.
- **Session binding.** ssh sends `session-bind@openssh.com`, which the agent
  verifies. The rules follow OpenSSH's ssh-agent:
  - a userauth signature is only made for the most recent binding on the
    connection
  - never for a binding made only to forward the agent
  - unbound sessions are refused unless `--require-session-bind=false`
  - any request on a connection with a forwarding binding (a login or a
    signature) is marked as forwarded: it comes from another host, and the
    local process details only describe the forwarding ssh

  The bound host key is named from known_hosts. Hashed entries are matched
  against the destination on ssh's command line.
- **Context.** The requesting process comes from `SO_PEERCRED`, and its
  ancestors from `/proc/<pid>/stat`.
  - **Tool run and scope.** The agent takes the unbroken run of `ssh`,
    `ssh-keygen`, `git`, `git-*`, `jj` and `phonekey-keygen` processes. The
    topmost one (pid and start time) is the request's scope, which is what
    grants match on. Only that run and its immediate parent are sent to the
    backend.
  - **ssh.** The destination and the git action ("push to stancl/foo") come
    from ssh's arguments.
  - **ssh-keygen.** The agent reads the file being signed, if it's a regular
    file. It uses the file only if its hash matches the one in the SSHSIG blob,
    and then parses it as a git commit or tag.
  - **Linux only.** Process inspection is Linux-only. Elsewhere requests simply
    carry less context.

### Page

- **No build step.** The page is plain ES modules with no framework and no
  third-party code apart from the vendored noble. All DOM is built with a small
  helper that only creates text nodes, never HTML strings.
- **Notifications** don't set `requireInteraction`: macOS Chrome only shows
  those if they're allowed as "alerts".
- **Live updates.** The page keeps an EventSource open. Browsers give up
  reconnecting after an HTTP error such as a proxy's 502, so the page
  reconnects by itself.
- **Preselection.** Only the request whose notification you tapped is
  preselected, or one that arrives alone into an empty list. Never several at
  once, so nothing gets swept into an approval unseen.
- **Grants** match the dev box, the scope and the key. They only sign userauth
  or SSHSIG data, never forwarded requests, and never while the page is hidden.
- **Key material** is wiped after each use: the PRF output, the seed copies, and
  the PKCS#8 buffer used to import the seed. A grant's key is wiped once its
  last signature is done.
- **Approvals.** Adding a key without a pairing code, and removing one, first
  ask for a registered passkey.

## Threat model

- **Trusted: the backend, including the page code it serves.** Whoever controls
  the backend can serve a page that copies the key at your next approval. That's
  the price of deriving an ordinary ed25519 key that GitHub accepts. So the
  backend runs apart from the dev boxes, serves only its own files, and sends a
  strict CSP. A stolen disk or backup of the backend holds no key material.
- **Browser extensions.** An extension that has access to the backend's site
  can run code inside the page and see the PRF output, so it can derive the key.
  No page-level isolation prevents that. Password managers that provide
  passkeys through an extension (e.g. 1Password in Chrome) see the PRF output
  by design. The cleanest place to approve is the iPhone home-screen app with
  iCloud Keychain, since iCloud Keychain passkeys go through iOS rather than an
  extension. On a desktop, use a browser profile without extensions, or keep
  extensions off the backend's site (per-extension site access, or Chrome's
  `runtime_blocked_hosts` policy).
- **Semi-trusted: the dev box.** Anything running as your user there can:
  - read the agent's token
  - send requests, which still need your approval
  - lie in everything it reports: command, process, server name, commit
    details, and the scope

  So during an open grant it could pass a request off as part of the granted
  command. It never gets key material. It can't get the page to sign a web
  login, because phonekeyd only queues userauth and SSHSIG data and the page
  refuses its own login format.

  Checking commit details against the signed hash wouldn't help: an attacker on
  the dev box writes the whole commit, message and change id included. What
  protects you is approving only what you just triggered: the timing, the
  command and the count.
- **Hosts you forward the agent to** (`ssh -A`) can request signatures too.
  Their requests are marked *Forwarded* and never auto-signed by a grant.
- **SSH logins.** Session binding limits signatures to real sessions with the
  server the client verified. With `--require-known-host`, that server has to
  be in known_hosts.
- **Other websites** can't use the passkey (it's bound to the backend's domain)
  or the web API (`SameSite=Strict` cookie, same-origin check).
- **A lost phone** still needs Face ID or the passcode for the passkey. To
  recover: remove the key from GitHub and from phonekeyd (the page or
  `keys rm`). That also ends every login it opened, cutting off live updates to
  a page still open on the phone, and stops notifications to those devices.
  Then pair again.
- **A stolen session cookie** can read pending requests (commands, commit
  messages, server names) and deny them. It can't sign: signing needs the
  passkey. It can't add or remove keys: that needs a passkey approval.
- **A stolen dev box token** can only queue requests, which you'd see and could
  deny. To recover: `devbox rm`.
- **Compared with 1Password's agent.** Both give one signature per approval and
  never put the key on the dev box. phonekey shows what's being signed. It's
  weaker in that the page's code can derive the key, while 1Password's key
  never leaves 1Password.

Not handled:
- rate limits: `nonce` is unauthenticated, and every request sends a push
- push endpoints aren't restricted to known push services, so self-hosted
  ones work. A stolen session could therefore make the backend send blind POSTs
  to any HTTPS address it can reach. The body is an encrypted notification, and
  the response isn't returned.
- a list of sessions to revoke one by one; removing a key ends all of its
  sessions at once
- an audit log beyond `--retention`
- a client that half-closes its socket is treated as disconnected (OpenSSH
  doesn't do this)

## Dependencies

Everything outside the Go standard library, by where it runs.

**The page** (where the key lives):

| Dependency | Used for |
| --- | --- |
| `@noble/ed25519` 3.2.0, vendored as `web/vendor/noble-ed25519.js` | always: computing the public key and checking every WebCrypto signature; signing when WebCrypto fails the RFC 8032 vectors |

It's a single file with no dependencies of its own. It's unmodified from npm, and
its integrity hash is in `web/vendor/README.md`. Nothing else runs in the page:
the CSP blocks other origins.

**phonekey-agent** (dev box):

| Dependency | Used for |
| --- | --- |
| `golang.org/x/crypto` | `ssh`, `ssh/agent`: the agent protocol, key and signature parsing |
| `golang.org/x/sys` | `SO_PEERCRED` |

phonekey-keygen uses only the standard library.

**phonekeyd** (backend):

| Dependency | Used for | Pulls in |
| --- | --- | --- |
| `golang.org/x/crypto`, `golang.org/x/sys` | SSH key and signature parsing | |
| `modernc.org/sqlite` | the database; SQLite translated to pure Go (no cgo) | `modernc.org/libc`, `mathutil`, `memory`; `remyoudompheng/bigfft`, `dustin/go-humanize`, `google/uuid` |
| `github.com/SherClockHolmes/webpush-go` | Web Push. A push is one HTTPS POST to the subscription's endpoint (Apple's or Google's push service), plus two pieces of cryptography: a VAPID token signed with phonekeyd's P-256 key, which proves the sender to the push service, and the payload encrypted to the subscription's key (RFC 8291), so the push service can't read it | `golang-jwt/jwt/v5` |
| `tailscale.com` (`tsnet`) | only for `--tailscale-hostname` | about 35 more modules: `wireguard-go`, gVisor's netstack, `x/net`, `klauspost/compress`, … |

Without `tsnet`, phonekeyd builds from 11 modules; with it, from 45. `go version -m
bin/phonekeyd` lists them.

**Tests only**, not in any binary: `chromedp/chromedp` and `chromedp/cdproto`, which
drive Chromium.

**Supply chain.**
- **No floating versions.** `go.mod` names exact versions, and Go's minimal
  version selection never picks a newer one by itself. Dependencies only change
  when someone edits `go.mod` (`go get`).
- **Hashes.** `go.sum` records a SHA-256 hash of each module's contents and of
  its `go.mod`. It works as the lockfile's hashes: the go command refuses a
  download that doesn't match.
- **Replaced tags.** The first time any version is fetched, the go command
  checks it against `sum.golang.org`, a public append-only log of module hashes.
  `proxy.golang.org` keeps serving the originally published contents. So a tag
  that's moved or force-pushed on GitHub later doesn't change what anyone
  builds: the contents no longer match the log, and the go command stops with a
  security error.
- **What this doesn't cover.** A malicious *new* version, published by a
  compromised maintainer, gets in only when you bump to it. So read the diff of
  a dependency before bumping it.
- **No install-time code.** Go has no install scripts like npm's
  `postinstall`. With cgo off, building runs no code from dependencies.
- **Nix.** `vendorHash` in `flake.nix` pins the hash of the complete vendored
  module set used by `nix build`. That's a second, independent check on top of
  `go.sum`: any change to any dependency's contents fails the build until the
  hash is updated on purpose. `flake.lock` pins nixpkgs, and with it the Go
  toolchain, for builds of this flake. Through the NixOS modules with
  `inputs.nixpkgs.follows`, the toolchain comes from your system's nixpkgs.
- **The page's one dependency** is vendored, with its npm integrity hash in
  `web/vendor/README.md`. Nothing is fetched at build or run time.
- **Tests only.** The e2e sshd image uses `alpine:3.22` by tag, not by digest.

**Pinning.**
- `tailscale.com` is held at v1.104.6, the newest release that builds with
  nixpkgs' Go 1.27.3.
- `govulncheck ./...` (2026-11-22) reports one issue, in the standard library:
  GO-2026-6859, an `net/http` server crash. It's fixed in Go 1.27.4, which
  nixpkgs doesn't have yet. Anyone who can reach phonekeyd (the tailnet,
  localhost) could crash it, and the NixOS service restarts after a crash.
- `klauspost/compress` and `golang-jwt/jwt/v5` were bumped past their advisories.

**Trimming options.**
- **`tsnet` behind a build tag**, for deployments that sit behind
  `tailscale serve`: removes ~35 modules from those builds.
- **A built-in Web Push implementation** instead of `webpush-go`: about 150
  lines on the standard library's ECDH, HKDF, AES-GCM and ECDSA, which also
  drops `golang-jwt`.

## Development

```sh
nix develop                    # or direnv (.envrc): go (nixpkgs toolchain, GOTOOLCHAIN=local), openssh, git, jj, chromium
go build -o bin/ ./cmd/...
go test ./internal/...         # unit and in-process integration
go test -tags e2e ./...        # everything, including e2e (needs docker and chromium)
nix build                      # the package
nix flake check                # the unit tests in Nix's sandbox, with the package's toolchain and modules
```

`e2e/` runs everything for real, with a temporary `HOME`, `GIT_CONFIG_GLOBAL`,
`JJ_CONFIG` and explicit ssh options, so the host's own setup is never touched:

- **`TestGit`, `TestJJ`, `TestCancelAndDeadline`** use OpenSSH, git and jj
  against a throwaway sshd container (`e2e/sshd`), with `internal/sim` approving.
  They cover:
  - clone, signed commit and tag, push and deny
  - the shared scope of a 3-commit `git rebase -S`
  - `jj git push` with sign-on-push: 2 signatures plus 1 login in one scope,
    commit subjects and change ids through the shim, `jj log` reporting `good`
  - cancelling with Ctrl-C, and the agent deadline
- **`TestBrowser`** drives the real page in headless Chromium, with a virtual
  authenticator that supports PRF:
  - pairing, and the JS key derivation matching Go
  - approving `ssh-keygen` signatures, and late arrivals not being preselected
  - removing keys: another key, then the one the page is logged in with
  - *Approve + rest* covering a rebase, and no grant offered for a one-shot
  - Recent
  - reconnecting after a 502
  - the diagnostics signature verifying with OpenSSH, through WebCrypto and
    through noble

  `PHONEKEY_SCREENSHOTS=dir` saves phone-sized screenshots.

**Development-only code.**

| Path | Purpose | Keep? |
| --- | --- | --- |
| `internal/sim` | a fake approver: a Go client of the page's web API, with its key derived from a fixed secret instead of a passkey's PRF output. To the backend it looks exactly like the page in a browser on any device. | yes, it approves for the git, jj and cancel e2e tests and most server tests |
| `cmd/phonekey-sim` | a command-line wrapper around `internal/sim`, for trying the dev box side by hand without a browser. Not in the Nix packages. | can go; the real page now covers manual testing |
| `tools/genicons` | renders `web/icon-*.png` from the same shapes as `web/icon.svg`; run once | can go; the PNGs stay |
| `e2e/` | the end-to-end tests | yes |

`phonekey-sim` pairs with a key derived from `--secret` and approves (or asks y/N
with `--ask`):

```sh
export PHONEKEY_DB=/tmp/phonekey.db
bin/phonekeyd serve &
bin/phonekey-sim pair "$(bin/phonekeyd pair-code)"
PHONEKEY_TOKEN=$(bin/phonekeyd devbox add test) bin/phonekey-agent --backend http://127.0.0.1:8080 --socket /tmp/pk.sock &
bin/phonekey-sim watch --ask
```

## Open questions and future work

- **GitHub.** How long it waits during an SSH login decides the agent's
  `--deadline`. Not measured.
- **A regression test for the NixOS module.** The module runs in production
  (the built-in tailnet mode, with the full sandbox, `phonekeyd-ctl` and the
  agent module). Nothing re-checks the isolation automatically, though, and the
  `serve.httpsPort` helper hasn't run yet. A `runNixOSTest` VM test would cover
  both; it needs KVM, e.g. in CI (GitHub's Linux runners have it).
- **Showing a range before approving.** A grant signs commits you only see
  afterwards. For `jj sign -r X`, the agent knows the command line and its
  working directory. It could run `jj log -r X --ignore-working-copy` there and
  attach the commits (subject, change id) to the first request, so the card
  shows "this command will sign: a, b, c, d" before you approve.
  - It's command-specific. `jj git push` decides what to sign from the pushed
    bookmarks and the sign-on-push revset, which is harder to reproduce, and
    `git rebase -S` would need its own handling.
  - The list could differ from what's actually signed, e.g. when jj skips
    commits that are already signed.
  - Like all dev box context, it's unverified.
- **Passkey-native signatures.** `webauthn-sk-ecdsa` signatures straight from the
  passkey, so not even the page holds a key. It works with OpenSSH servers but
  not GitHub.
