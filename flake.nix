{
  description = "phonekey: approve SSH logins and commit signatures with a passkey";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # One Go build of some of the module's packages; they all share the
      # source and the vendored modules.
      goBuild = pkgs: { pname, subPackages, mainProgram ? null, doCheck ? false }: pkgs.buildGoModule {
        inherit pname subPackages doCheck;
        version = "0.1.0";
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [ ./go.mod ./go.sum ./cmd ./internal ./web ];
        };
        vendorHash = "sha256-jR72jh6BY9G5zVY1s5pPlv+4xiUprdBn16HwSipkv/Q=";
        env.CGO_ENABLED = "0";
        ldflags = [ "-s" "-w" ];
        meta = pkgs.lib.optionalAttrs (mainProgram != null) { inherit mainProgram; };
      };
    in
    {
      packages = forAll (pkgs: rec {
        # The backend, for the host that serves phonekey.
        phonekeyd = goBuild pkgs {
          pname = "phonekeyd";
          subPackages = [ "cmd/phonekeyd" ];
          mainProgram = "phonekeyd";
        };
        # The dev box side: the agent, and the ssh-keygen shim for jj.
        phonekey-agent = goBuild pkgs {
          pname = "phonekey-agent";
          subPackages = [ "cmd/phonekey-agent" "cmd/phonekey-keygen" ];
          mainProgram = "phonekey-agent";
        };
        default = pkgs.symlinkJoin {
          name = "phonekey";
          paths = [ phonekeyd phonekey-agent ];
        };
      });

      # Unit and in-process integration tests, built with the package's
      # toolchain and vendored modules. The e2e tests need Docker and a
      # browser, so they run outside Nix: go test -tags e2e ./e2e
      checks = forAll (pkgs: {
        tests = goBuild pkgs {
          pname = "phonekey-tests";
          subPackages = [ "internal/..." "cmd/..." ];
          doCheck = true;
        };
      });

      # Both modules; each does nothing until its options are set.
      nixosModules.default = {
        imports = [ self.nixosModules.phonekeyd self.nixosModules.phonekey-agent ];
      };

      # The backend as NixOS services: one instance per person, each under its
      # own system account.
      nixosModules.phonekeyd = { config, lib, pkgs, ... }:
        let
          cfg = config.services.phonekeyd;
          instances = lib.filterAttrs (_: i: i.enable) cfg.instances;
          user = name: "phonekeyd-${name}";
          stateDir = name: "/var/lib/phonekeyd/${name}";
          socket = name: "/run/phonekeyd-${name}/http.sock";
          # The plain listener: an explicit address, or a socket only the
          # instance's account (and root's tailscaled) can open when it isn't
          # on its own tailnet machine.
          listen = name: i:
            if i.address != null then i.address
            else if i.tailscale.hostname == null then "unix:${socket name}"
            else null;
          # The sandbox every instance runs in, so that a compromised phonekeyd
          # (a bug, or a malicious dependency) can't reach beyond its own state:
          # not other services, accounts or instances on the host.
          sandbox = name: {
            User = user name;
            Group = user name;
            StateDirectory = "phonekeyd/${name}";
            StateDirectoryMode = "0700";
            UMask = "0077";
            CapabilityBoundingSet = "";
            AmbientCapabilities = "";
            NoNewPrivileges = true;
            PrivateUsers = true;
            PrivateTmp = true;
            PrivateDevices = true;
            PrivateIPC = true;
            RemoveIPC = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            # The process can't see other accounts' processes in /proc.
            ProtectProc = "invisible";
            ProcSubset = "pid";
            ProtectClock = true;
            ProtectHostname = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectKernelLogs = true;
            ProtectControlGroups = true;
            RestrictNamespaces = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            SystemCallArchitectures = "native";
            # EPERM rather than a kill: Go's runtime calls setrlimit at startup.
            SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
            SystemCallErrorNumber = "EPERM";
            # The host's tailscaled, D-Bus and shared memory are off limits.
            InaccessiblePaths = [ "-/run/tailscale" "-/run/dbus" "-/var/run/dbus" "-/dev/shm" ];
            # Only programs from the Nix store run, not files it wrote.
            NoExecPaths = "/";
            ExecPaths = "/nix/store";
            MemoryMax = "512M";
            TasksMax = 256;
            CPUQuota = "100%";
            IOWeight = 20;
          };
          # systemd-run's -p form of a service config.
          toProperties = attrs: lib.concatLists (lib.mapAttrsToList (k: v:
            [ "-p" "${k}=${if lib.isList v then lib.concatStringsSep " " (map toString v) else if lib.isBool v then lib.boolToString v else toString v}" ]
          ) attrs);
          # Admin commands (pair-code, devbox add, keys) on an instance's
          # database: run as its account, in its sandbox, without network.
          ctl = pkgs.writeShellScriptBin "phonekeyd-ctl" ''
            if [ $# -lt 2 ]; then
              echo "usage: phonekeyd-ctl INSTANCE COMMAND [ARGS...]" >&2
              echo "instances: ${lib.concatStringsSep " " (lib.attrNames instances)}" >&2
              exit 2
            fi
            name=$1; shift
            case "$name" in
            ${lib.concatMapStrings (name: ''
              ${name}) exec ${config.systemd.package}/bin/systemd-run --quiet --pipe --wait --collect --service-type=exec \
                ${lib.escapeShellArgs (toProperties (sandbox name // { PrivateNetwork = true; }))} \
                -- ${lib.getExe cfg.package} --db ${stateDir name}/phonekey.db "$@" ;;
            '') (lib.attrNames instances)}
            *) echo "phonekeyd-ctl: unknown instance $name" >&2; exit 2 ;;
            esac
          '';
          # Where a TCP listener is used, incoming connections must stay
          # possible, so the address restrictions only apply otherwise.
          tcpListener = name: i: listen name i != null && !lib.hasPrefix "unix:" (listen name i);
          instanceOptions = { name, ... }: {
            options = {
              enable = lib.mkEnableOption "this instance" // { default = true; };
              vapidSubject = lib.mkOption {
                type = lib.types.str;
                example = "you@example.com";
                description = "Contact for push services: an email address or an https: URL.";
              };
              tailscale = {
                hostname = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  example = "phonekey";
                  description = ''
                    Join the tailnet as its own machine with this name and serve
                    https://<hostname>.<tailnet>.ts.net. Nothing listens on the host.
                    Needs MagicDNS and HTTPS enabled for the tailnet.
                  '';
                };
                authKeyFile = lib.mkOption {
                  # A string, not a path: ./key would be copied into the Nix store.
                  type = lib.types.nullOr (lib.types.strMatching "/.*");
                  default = null;
                  example = "/run/secrets/phonekey-ts-authkey";
                  description = ''
                    Tailscale auth key for the first login, as an absolute path outside
                    the Nix store. It must exist whenever the service starts. Without
                    one, the service logs a URL to approve the machine
                    (journalctl -u phonekeyd-<name>).
                  '';
                };
              };
              serve.httpsPort = lib.mkOption {
                type = lib.types.nullOr lib.types.port;
                default = null;
                example = 8443;
                description = ''
                  Publish this instance through the host's tailscale serve on this
                  HTTPS port (https://<host>.<tailnet>.ts.net:<port>), proxying to the
                  instance's Unix socket. For instances without tailscale.hostname.
                '';
              };
              address = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "127.0.0.1:8080";
                description = ''
                  Plain HTTP listener (host:port or unix:/path) instead of the
                  default: /run/phonekeyd-<name>/http.sock without
                  tailscale.hostname, nothing with it. The socket is open to the
                  account and group phonekeyd-<name> only; a reverse proxy such as
                  nginx gets access by joining that group. A TCP address is reachable
                  by every account on the host.
                '';
              };
              ipAddressAllow = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                example = [ "192.168.1.1" ];
                description = ''
                  Addresses the instance may reach despite the ban on the host,
                  link-local, private and tailnet ranges, e.g. a DNS resolver on the
                  LAN. systemd-resolved's stub, Tailscale's MagicDNS resolver and
                  networking.nameservers are always allowed.
                '';
              };
              extraArgs = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                example = [ "--max-grant" "30s" ];
                description = "Extra arguments for `phonekeyd serve`.";
              };
            };
          };
        in
        {
          # Imported once, even through both .default and .phonekeyd.
          key = "phonekey/phonekeyd";
          options.services.phonekeyd = {
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.phonekeyd;
              description = "Package providing phonekeyd.";
            };
            instances = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule instanceOptions);
              default = { };
              description = ''
                Backends to run, one per person. Each runs as its own system account
                phonekeyd-<name>, with its state in /var/lib/phonekeyd/<name>.
              '';
            };
          };

          config = lib.mkIf (instances != { }) {
            assertions = lib.concatLists (lib.mapAttrsToList (name: i: [
              {
                assertion = builtins.match "[a-z][a-z0-9-]{0,21}" name != null;
                message = "services.phonekeyd.instances.${name}: names are lowercase letters, digits and dashes, at most 22 characters.";
              }
              {
                assertion = i.serve.httpsPort == null || (i.tailscale.hostname == null && i.address == null);
                message = "services.phonekeyd.instances.${name}: serve.httpsPort publishes the instance's Unix socket, so it can't be combined with tailscale.hostname or address.";
              }
              {
                assertion = i.tailscale.authKeyFile == null || !lib.hasPrefix builtins.storeDir i.tailscale.authKeyFile;
                message = "services.phonekeyd.instances.${name}: tailscale.authKeyFile is in the Nix store, readable by everyone; use a path outside it.";
              }
              {
                assertion = i.serve.httpsPort == null || config.services.tailscale.enable;
                message = "services.phonekeyd.instances.${name}: serve.httpsPort needs services.tailscale.enable.";
              }
            ]) instances) ++ [
              {
                # Browsers treat every port of a hostname as one site: instances
                # sharing the host's name would share cookies and passkeys.
                assertion = lib.length (lib.filter (i: i.serve.httpsPort != null) (lib.attrValues instances)) <= 1;
                message = "services.phonekeyd: at most one instance can use serve.httpsPort (the host's hostname); give the others tailscale.hostname.";
              }
            ];

            users.users = lib.mapAttrs' (name: _: lib.nameValuePair (user name) {
              isSystemUser = true;
              group = user name;
              home = stateDir name;
            }) instances;
            users.groups = lib.mapAttrs' (name: _: lib.nameValuePair (user name) { }) instances;
            environment.systemPackages = [ ctl ];

            systemd.services = lib.mkMerge (lib.mapAttrsToList (name: i: {
              ${user name} = {
                description = "phonekey backend (${name})";
                wantedBy = [ "multi-user.target" ];
                wants = [ "network-online.target" ];
                after = [ "network-online.target" ];
                # Keep restarting after crashes, however many.
                startLimitIntervalSec = 0;
                serviceConfig = {
                  ExecStart = lib.escapeShellArgs (
                    [ (lib.getExe cfg.package) "--db" "${stateDir name}/phonekey.db" "serve" "--vapid-subject" i.vapidSubject ]
                    ++ lib.optionals (listen name i != null) [ "--addr" (listen name i) ]
                    ++ lib.optionals (i.tailscale.hostname != null) [ "--tailscale-hostname" i.tailscale.hostname ]
                    ++ lib.optionals (i.tailscale.authKeyFile != null) [ "--tailscale-authkey-file" "%d/tailscale-authkey" ]
                    ++ i.extraArgs
                  );
                  LoadCredential = lib.optional (i.tailscale.authKeyFile != null) "tailscale-authkey:${i.tailscale.authKeyFile}";
                  RuntimeDirectory = user name;
                  RuntimeDirectoryMode = "0750";
                  Restart = "on-failure";
                  RestartSec = 2;
                  # Binding host ports: tsnet's WireGuard socket (UDP), or the TCP
                  # listener. Connections out don't bind.
                  SocketBindDeny = "any";
                  SocketBindAllow = lib.optional (i.tailscale.hostname != null) "udp"
                    ++ lib.optional (tcpListener name i) "tcp:${lib.last (lib.splitString ":" (listen name i))}";
                  # Outbound HTTPS for push; netlink only for tsnet.
                  RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ]
                    ++ lib.optional (i.tailscale.hostname != null) "AF_NETLINK";
                } // sandbox name // lib.optionalAttrs (!tcpListener name i) {
                  # Nothing on the host or the local networks: push services and
                  # the tailnet's control and relay servers are on the internet.
                  # (tsnet's own tailnet traffic is userspace and needs ACLs.)
                  IPAddressDeny = [ "localhost" "link-local" "multicast" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "100.64.0.0/10" "fc00::/7" ];
                  # systemd-resolved's stub, and Tailscale's MagicDNS (IPv4, IPv6).
                  IPAddressAllow = [ "127.0.0.53" "100.100.100.100" "fd7a:115c:a1e0::53" ] ++ config.networking.nameservers ++ i.ipAddressAllow;
                };
              };
              "${user name}-serve" = lib.mkIf (i.serve.httpsPort != null) {
                description = "tailscale serve for phonekey (${name})";
                wantedBy = [ "multi-user.target" ];
                after = [ "tailscaled.service" (user name + ".service") ];
                wants = [ "tailscaled.service" ];
                serviceConfig = {
                  Type = "oneshot";
                  RemainAfterExit = true;
                  # Root, but only to talk to tailscaled's socket.
                  PrivateNetwork = true;
                  PrivateTmp = true;
                  PrivateDevices = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  NoNewPrivileges = true;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictAddressFamilies = [ "AF_UNIX" ];
                  CapabilityBoundingSet = "";
                  ExecStart = "${lib.getExe config.services.tailscale.package} serve --bg --https=${toString i.serve.httpsPort} unix:${socket name}";
                  ExecStop = "${lib.getExe config.services.tailscale.package} serve --https=${toString i.serve.httpsPort} off";
                };
              };
            }) instances);
          };
        };

      # The dev box side: phonekey-agent as a systemd user service for the
      # listed users, each with their own backend, plus ssh pointed at it for
      # chosen hosts. git and jj sign through phonekey-keygen, which finds the
      # agent's socket by itself, so nothing needs SSH_AUTH_SOCK. The same
      # module serves nix-darwin (darwinModules.phonekey-agent), with a launchd
      # agent for the user unit.
      nixosModules.phonekey-agent = { config, lib, options, pkgs, ... }:
        let
          cfg = config.programs.phonekey-agent;
          # Which modules imported this, from the options alone, so not from
          # config, which this decides.
          darwin = options ? launchd;
          # The agent's socket, as ssh_config writes it. macOS has no
          # XDG_RUNTIME_DIR, where the agent puts it by default, so there the
          # settings file names it.
          socket = if darwin then "~/.ssh/phonekey-agent.sock" else "/run/user/%i/phonekey-agent.sock";
          # One launchd agent for every user, as there's one user unit: it
          # runs the agent only for the listed users, once their token exists,
          # with their settings file's environment.
          darwinStart = pkgs.writeShellScript "phonekey-agent-start" ''
            settings=/etc/phonekey/agent/$(/usr/bin/id -un).env
            [ -r "$settings" ] || exit 0
            # As ConditionPathExists, but launchd has none: wait for the token.
            while [ ! -e "$HOME/.config/phonekey/token" ]; do sleep 60; done
            # As EnvironmentFile: values stay literal, the agent expands $HOME.
            while IFS= read -r line; do
              if [ -n "$line" ]; then export "$line"; fi
            done <"$settings"
            exec >>"$HOME/Library/Logs/phonekey-agent.log" 2>&1
            exec ${lib.getExe cfg.package}
          '';
          # A configured key path as a shell word, with ~/ meaning $HOME.
          shellPath = path:
            if lib.hasPrefix "~/" path then ''"$HOME"/${lib.escapeShellArg (lib.removePrefix "~/" path)}''
            else lib.escapeShellArg path;
          # phonekey-use NAME|FILE points two links at public keys (a name
          # from identities, or one key file for both):
          # ~/.ssh/active.pub, which git and jj sign commits with, and
          # ~/.ssh/active_auth.pub, which ssh logs in with (ssh.hosts).
          use = name: u: pkgs.writeShellScriptBin "phonekey-use" ''
            set -eu
            sign_link="$HOME/.ssh/active.pub"
            auth_link="$HOME/.ssh/active_auth.pub"
            show() {
              for l in "$sign_link" "$auth_link"; do
                if [ -L "$l" ]; then echo "$l -> $(readlink "$l")"; else echo "$l: not set"; fi
              done
            }
            if [ $# -eq 0 ]; then
              show
              echo names: ${lib.escapeShellArg (lib.concatStringsSep " " (lib.attrNames u.identities))}
              exit 0
            fi
            case "$1" in
            ${lib.concatStrings (lib.mapAttrsToList (n: id: ''
              ${lib.escapeShellArg n}) sign=${shellPath id.sign}; auth=${shellPath id.auth} ;;
            '') u.identities)}
            /*) sign="$1"; auth="$1" ;;
            *) sign="$PWD/$1"; auth="$PWD/$1" ;;
            esac
            for k in "$sign" "$auth"; do
              if [ ! -e "$k" ]; then echo "phonekey-use: $k doesn't exist" >&2; exit 1; fi
            done
            mkdir -p -m 700 "$HOME/.ssh"
            ln -sfn "$sign" "$sign_link"
            ln -sfn "$auth" "$auth_link"
            show
          '';
          # A key for signing and logging in, or one key for both.
          identity = lib.types.coercedTo lib.types.str (path: { sign = path; auth = path; }) (lib.types.submodule {
            options = {
              sign = lib.mkOption { type = lib.types.str; description = "Key git and jj sign commits with."; };
              auth = lib.mkOption { type = lib.types.str; description = "Key ssh logs in with."; };
            };
          });
          userOptions = {
            options = {
              backend = lib.mkOption {
                type = lib.types.str;
                example = "https://phonekey.tail1234ab.ts.net";
                description = "The user's phonekeyd.";
              };
              upstream = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "$XDG_RUNTIME_DIR/op-agent.sock";
                description = "Another agent whose keys to offer too, e.g. a forwarded 1Password agent.";
              };
              identities = lib.mkOption {
                type = lib.types.attrsOf identity;
                default = { phone = "~/.ssh/phonekey.pub"; };
                example = lib.literalExpression ''
                  {
                    phone = "~/.ssh/phonekey.pub";
                    desktop = { sign = "~/.ssh/op-github.pub"; auth = "~/.ssh/op-github_auth.pub"; };
                  }
                '';
                description = ''
                  Names for `phonekey-use`, e.g. `phonekey-use desktop`. Each is one
                  key for both signing and logins, or a separate `sign` and `auth`
                  key.
                '';
              };
              ssh.hosts = lib.mkOption {
                # One ssh_config pattern each; whitespace or a comma would break
                # /etc/ssh/ssh_config for every user.
                type = lib.types.listOf (lib.types.strMatching "[^[:space:],]+");
                default = [ "github.com" ];
                example = [ "github.com" "git.example.com" ];
                description = ''
                  Hosts ssh reaches through the agent, logging in with only the key
                  ~/.ssh/active_auth.pub points at (IdentityAgent, IdentityFile,
                  IdentitiesOnly, in the system ssh_config). Other hosts keep the
                  user's usual setup. The user's own ~/.ssh/config takes precedence;
                  an IdentityFile there is tried before this one. To use the agent
                  for every host, point SSH_AUTH_SOCK at it instead.
                '';
              };
            };
          };
        in
        {
          # Imported once, even through both .default and .phonekey-agent.
          key = "phonekey/phonekey-agent";
          options.programs.phonekey-agent = {
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.phonekey-agent;
              description = "Package providing phonekey-agent and phonekey-keygen.";
            };
            users = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule userOptions);
              default = { };
              description = "Users (who must exist) to run the agent for, and their settings.";
            };
          };

          config = lib.mkIf (cfg.users != { }) ({
            # Per-user settings, read by the one user unit below via %u. The
            # token itself stays in the user's home directory.
            environment.etc = lib.mapAttrs' (name: u: lib.nameValuePair "phonekey/agent/${name}.env" {
              text = ''
                PHONEKEY_BACKEND=${u.backend}
                PHONEKEY_TOKEN_FILE=$HOME/.config/phonekey/token
              '' + lib.optionalString (u.upstream != null) ''
                PHONEKEY_UPSTREAM=${u.upstream}
              '' + lib.optionalString darwin ''
                PHONEKEY_SOCKET=$HOME/.ssh/phonekey-agent.sock
              '';
            }) cfg.users;

            users.users = lib.mapAttrs (name: u: { packages = [ cfg.package (use name u) ]; }) cfg.users;

            programs.ssh.extraConfig = lib.concatStrings (lib.mapAttrsToList (name: u:
              lib.optionalString (u.ssh.hosts != [ ]) ''
                Match localuser ${name} host ${lib.concatStringsSep "," u.ssh.hosts}
                  IdentityAgent ${socket}
                  IdentityFile ~/.ssh/active_auth.pub
                  IdentitiesOnly yes
              '') cfg.users);
          } // (if darwin then {
            launchd.user.agents.phonekey-agent.serviceConfig = {
              ProgramArguments = [ "${darwinStart}" ];
              RunAtLoad = true;
              # Again after a crash or a failed start, not after exit 0: a
              # user without settings, or a clean stop.
              KeepAlive.SuccessfulExit = false;
              ThrottleInterval = 30;
              ProcessType = "Background";
            };
          } else {
            systemd.user.services.phonekey-agent = {
              description = "phonekey ssh-agent";
              wantedBy = [ "default.target" ];
              # Starts only for the listed users, once they've stored their dev
              # box token (kept out of the Nix store) in ~/.config/phonekey/token.
              unitConfig.ConditionPathExists = [ "/etc/phonekey/agent/%u.env" "%h/.config/phonekey/token" ];
              serviceConfig = {
                EnvironmentFile = "/etc/phonekey/agent/%u.env";
                ExecStart = lib.getExe cfg.package;
                Restart = "on-failure";
                RestartSec = 5;
              };
            };
          }));
        };

      # The agent for nix-darwin: the module above, with the same options.
      darwinModules.phonekey-agent = self.nixosModules.phonekey-agent;
      darwinModules.default = self.darwinModules.phonekey-agent;

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            openssh
            git
            jujutsu
            sqlite
            jq
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            # Headless browser for the WebAuthn virtual-authenticator test.
            chromium
          ];
          env.CGO_ENABLED = "0";
          # Build with the toolchain from nixpkgs, as the package does, instead of
          # letting go download whatever go.mod asks for.
          env.GOTOOLCHAIN = "local";
        };
      });
    };
}
