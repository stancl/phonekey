# Quickstart: NixOS, Tailscale, iPhone

One concrete setup, end to end:
- the backend on a NixOS host, as its own tailnet machine
- an iPhone as the approver
- the agent on a NixOS dev box (the same machine or another one), which also
  offers the keys of a 1Password agent forwarded from your Mac, so you can
  approve with 1Password at the desk and with the phone everywhere else
  ([forwarding 1Password](#forwarding-1password))

Replace `YOURTAILNET` with your tailnet's name (e.g. `tail1234ab`), and `you` with
your user name. The [README](README.md) covers the other setups and how it all
works.

Before you start: in the Tailscale admin console, under DNS, MagicDNS and HTTPS
certificates must be on.

## 1. The backend

In the host's system flake (`/etc/nixos/flake.nix`):

```diff
   inputs = {
     nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
+    phonekey.url = "github:stancl/phonekey";
+    phonekey.inputs.nixpkgs.follows = "nixpkgs";
   };

-  outputs = { nixpkgs, ... }: {
+  outputs = { nixpkgs, phonekey, ... }: {
     nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
       modules = [
         ./configuration.nix
+        phonekey.nixosModules.phonekeyd
+        {
+          services.phonekeyd.instances.you = {
+            vapidSubject = "https://phonekey.YOURTAILNET.ts.net";
+            tailscale.hostname = "phonekey";
+          };
+        }
       ];
```

```sh
sudo nixos-rebuild switch --flake /etc/nixos#myhost
journalctl -u phonekeyd-you -f
```

The log shows a `login.tailscale.com` link. Open it and approve the new
`phonekey` machine. A few seconds later the log says
`listening url=https://phonekey.YOURTAILNET.ts.net`. The site can take a minute
to load the first time, while the certificate is issued.

`interfaces: failed to read /proc/net/route` in the log can be ignored; the
sandbox hides that file.

**Optional: keep it from reaching your other machines.** The machine is
approved with your account, so the default tailnet policy lets it connect to
all your devices, like any of them. The systemd sandbox doesn't cover this:
phonekeyd talks to the tailnet from inside the process. It only matters if
phonekeyd itself is compromised. To close it, tag the machine, which takes it
out of "your devices", and allow connections only from your devices.

## 2. The phone

1. Open `https://phonekey.YOURTAILNET.ts.net` in Safari, then Share → **Add to
   Home Screen**, and open phonekey from the home screen. Push notifications
   only work in the installed app.
2. On the host: `sudo phonekeyd-ctl you pair-code`. Enter the code in the app.
3. Tap **Create passkey**. For iCloud Keychain, pick *Passwords* if iOS offers
   1Password first. If you already have a phonekey passkey for this hostname,
   tap **Use an existing passkey** instead.
4. Copy the `ssh-ed25519 …` key it shows.
5. Under **Notifications, grants and keys**: **Enable notifications**, then
   **Send test**.

On GitHub, add the key as a **Signing key**, and as an **Authentication key**
once you trust the setup.

## 3. The dev box

In the dev box's system flake (with the same `phonekey` input as above; on
the same machine as the backend, `phonekey.nixosModules.default` brings both
modules):

```nix
phonekey.nixosModules.phonekey-agent
{
  programs.phonekey-agent.users.you = {
    backend = "https://phonekey.YOURTAILNET.ts.net";
    # Also offer the keys of the forwarded 1Password agent, while it's connected.
    upstream = "$XDG_RUNTIME_DIR/op-agent.sock";
    # Names for `phonekey-use`: one key for both signing and logins, or a pair.
    identities = {
      phone = "~/.ssh/phonekey.pub";
      desktop = { sign = "~/.ssh/op-github.pub"; auth = "~/.ssh/op-github_auth.pub"; };
    };
    # Hosts ssh reaches through the agent (the default).
    # ssh.hosts = [ "github.com" ];
  };
}
```

That gives `you`:
- the agent as a systemd user service
- `phonekey-agent`, `phonekey-keygen`, `phonekey-use` and `phonekey-enroll` in
  your `PATH`
- for the hosts in `ssh.hosts`, ssh going through the agent, logging in with
  only the key `~/.ssh/active_auth.pub` points at. Every other host keeps your
  usual setup: your `~/.ssh` keys and `SSH_AUTH_SOCK`.

These live in the system's ssh_config; your own `~/.ssh/config` still wins.

How it fits together:
- **Who asks the agent:** ssh (for github.com) and `phonekey-keygen` (which
  git and jj run to sign) both ask phonekey-agent.
- **What it does with the request:** it sends a phone key to the phone, and
  your 1Password keys to the forwarded 1Password agent (`upstream`).
- **Which key is asked for:** two links decide. `~/.ssh/active.pub` is the key
  git and jj sign with, and `~/.ssh/active_auth.pub` the key ssh logs in
  with. `phonekey-use` sets both.

So nothing needs `SSH_AUTH_SOCK`. If you'd rather point `SSH_AUTH_SOCK` at
phonekey-agent in your shell, that works too, and makes git's `gpg.ssh.program`
line below unnecessary. Keep jj's `program = "phonekey-keygen"` either way: it's
what lets the phone show jj's commits. See
[README section 4](README.md#4-point-git-jj-and-ssh-at-it).

```sh
sudo nixos-rebuild switch --flake /etc/nixos#mydevbox
phonekey-enroll                            # optionally --name mydevbox; the default is the hostname
```

`phonekey-enroll` asks the backend to register the dev box and prints a code.
The phone gets a notification: open the *Add a dev box* card, check that it
shows the same code, and tap **Approve**. Once you have, the command stores
the dev box's token in `~/.config/phonekey/token` and (re)starts the agent.
From the next login on it starts by itself. Its log:

```sh
journalctl --user -u phonekey-agent -f
```

Without the phone at hand, `sudo phonekeyd-ctl you devbox add mydevbox` on the
backend host prints a token instead. Put it in `~/.config/phonekey/token`
(mode 600) and run `systemctl --user start phonekey-agent`.

Until you've finished step 4, ssh to the hosts in `ssh.hosts` fails for you:
it already goes through the agent and `~/.ssh/active_auth.pub`.

## 4. Your keys and tools

Save the phone key, and make it the active one. The agent lists it with the
comment `phonekey`, next to the 1Password keys:

```sh
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/phonekey-agent.sock ssh-add -L | grep ' phonekey$' > ~/.ssh/phonekey.pub
phonekey-use phone
```

```nu
# the same in nushell
with-env { SSH_AUTH_SOCK: $"($env.XDG_RUNTIME_DIR)/phonekey-agent.sock" } { ssh-add -L } | lines | where ($it | str ends-with ' phonekey') | save -f ~/.ssh/phonekey.pub
phonekey-use phone
```

`ssh-keygen -lf ~/.ssh/phonekey.pub` should print the fingerprint the app
shows. With several passkeys registered, every one is listed; keep the line
that matches.

Check that signing works, before touching any other config:

```sh
echo hello | phonekey-keygen -Y sign -f ~/.ssh/phonekey.pub -n file
```

A notification arrives on the phone. After you approve, the command prints a
`-----BEGIN SSH SIGNATURE-----` block. This goes through the same
`phonekey-keygen` and agent that git and jj will use, and works the same in
nushell.

git and jj sign with whatever `~/.ssh/active.pub` points at, and ssh logs in
to GitHub with `~/.ssh/active_auth.pub`. Switch both with:
- `phonekey-use phone`: approve on the phone, one key for both
- `phonekey-use desktop`: approve with 1Password, with its separate signing and
  login keys; needs the forwarded agent, see [below](#forwarding-1password)
- `phonekey-use` on its own shows both links

If your own `~/.ssh/config` has a `Host github.com` block with an
`IdentityFile`, remove it: your own config wins, so ssh would try that key
first. For ssh logins with the phone key, add it on GitHub as an
*Authentication* key too.

**git** (`~/.config/git/config`). `phonekey-keygen` finds the agent by itself:

```ini
[gpg]
	format = ssh
[gpg "ssh"]
	program = phonekey-keygen
[user]
	signingkey = ~/.ssh/active.pub
```

**jj** (`~/.config/jj/config.toml`). Nothing is signed automatically; you sign
deliberately, with `jj sign -r a..d` before pushing:

```toml
[signing]
behavior = "drop"
backend = "ssh"
key = "~/.ssh/active.pub"

[signing.backends.ssh]
program = "phonekey-keygen"
allowed-signers = "~/.ssh/allowed_signers"
```

Signing a range is one command, so it's one approval: tap **Approve + rest of
"jj sign …"** on the first commit, and the others are signed as they come in.

`allowed-signers` is only for showing signatures as good in `jj log`. List the
phone key there with your commit email, next to any older keys you signed with:

```nu
$"you@example.com (open ~/.ssh/phonekey.pub | str trim)\n" | save --append ~/.ssh/allowed_signers
```

For git, the same file is `gpg.ssh.allowedSignersFile`.

ssh needs no config of your own for GitHub: the module sets it up.

## 5. Day to day

**Who approves** follows `phonekey-use`:
- `phonekey-use phone`: everything goes to the phone
- `phonekey-use desktop`: everything goes to 1Password on the Mac. It needs
  the forwarding running ([below](#forwarding-1password)), or signing and
  logins fail.
- `phonekey-use ~/.ssh/other.pub`: one key file for both
- `phonekey-use`: shows where the two links point

The choice applies to the whole dev box, every shell at once. Short aliases help,
e.g. in nushell's `config.nu`:

```nu
alias mobile = phonekey-use phone
alias phone = phonekey-use phone
alias desktop = phonekey-use desktop
```

**Signing.** Nothing is signed until you ask:

```sh
jj sign -r 'a..d'
```

That's one command, so with the phone it's one approval. Tap **Approve + rest of
"jj sign …"** on the first commit's card, and the others are signed as they
arrive; the banner lists them. Plain **Approve** signs just that one, and the
next commit asks again.

**Pushing** is one SSH login, so one approval:

```sh
jj git push -b main
```

A quick check of logins on their own: `ssh -T git@github.com`.

**On the phone,** each request is a card:
- **The signed data:** what kind of request it is, the key, and for logins the
  server's key.
- **What the dev box says:** the command, the server, and the commit's
  subject, author and change id.

**Deny** makes the command on the dev box fail. A request you leave alone
expires after 90 seconds, and Ctrl-C on the dev box withdraws it. **Recent**
lists what was signed, and whether you or a grant approved it.

## Updating

After new commits are pushed to the phonekey repository:

```sh
sudo nix flake update phonekey --flake /etc/nixos
sudo nixos-rebuild switch --flake /etc/nixos#myhost
systemctl --user restart phonekey-agent    # on dev boxes
```

The database, the tailnet machine and your passkey stay. No re-pairing is
needed unless the hostname changes.

**Moving the backend to another host.** Copy `/var/lib/phonekeyd/you` over
(with the service stopped on both sides), and nothing changes: same tailnet
machine, keys, dev boxes and notifications. Starting fresh under the same
hostname instead, delete the old machine in the Tailscale admin console, pair
with **Use an existing passkey** (the same key, so GitHub stays as it is), tap
**Enable notifications** again, and enroll the dev boxes again (remove
`~/.config/phonekey/token` on each, then `phonekey-enroll`). A new hostname
means a new passkey and key.

## When something's off

- **`Load key "….pub": bad permissions` / `Permission denied (publickey)`.** The
  agent ssh talks to doesn't have that key. Either the agent isn't running
  (`systemctl --user status phonekey-agent`), your own `~/.ssh/config` points
  ssh at another agent or another `IdentityFile`, or the links point at the
  1Password keys while the forwarded agent isn't connected. GitHub also only
  asks for a signature with a key registered there as an Authentication key.
- **The agent doesn't start:** it's skipped while `~/.config/phonekey/token`
  doesn't exist. `phonekey-enroll` gets one and starts it.
- **No notification:** check **Send test** in the app, and that the request
  shows up in the app at all (if so, it's the notification side). The
  backend logs what the push service answered:
  `journalctl -u phonekeyd-you | grep push`.
- **The agent still uses the old backend:** restart it
  (`systemctl --user restart phonekey-agent`); a rebuild doesn't.
- **The page shows "reconnecting…":** it reconnects by itself; **Reload** in
  the header forces it.

## Forwarding 1Password

For `phonekey-use desktop`, the dev box needs your Mac's 1Password agent. A
dedicated ssh host on the Mac forwards it to a fixed path on the dev box, which
`upstream` above points at. In the Mac's `~/.ssh/config`:

```
Host devbox-agent
  HostName devbox
  RemoteForward /run/user/1000/op-agent.sock "/Users/YOU/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
  ExitOnForwardFailure yes
  ServerAliveInterval 30
  ServerAliveCountMax 3
  SessionType none
```

- **Running it:** `ssh devbox-agent` opens no shell; it only holds the
  forwarding open. Keep it running while you work at the Mac.
- **The path:** `/run/user/1000` is your `$XDG_RUNTIME_DIR` on the dev box
  (`1000` is your user id there).
- **On the dev box,** sshd must be allowed to replace a stale socket from an
  earlier connection, or the forwarding fails after the first disconnect:
  ```nix
  services.openssh.settings.StreamLocalBindUnlink = "yes";
  ```
