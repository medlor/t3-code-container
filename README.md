# T3 Code in rootless Podman on WSL2

Run T3, Codex, Claude Code and their terminal processes in a rootless container.
The selected project is mounted read/write at `/workspace`. The container uses
`--userns=keep-id` and your Linux UID/GID, so files it creates belong to you.

Install the host prerequisites inside WSL2 as your ordinary Linux user:

```bash
sudo apt update
sudo apt install -y podman uidmap slirp4netns fuse-overlayfs make python3 python3-yaml curl
podman info --format '{{.Host.Security.Rootless}}' # must print true
```

Use distribution Python (`/usr/bin/python3`) if a virtual environment shadows
`python3` without PyYAML. The launcher never installs host dependencies. Rootless
Podman needs a free, nonoverlapping subordinate ID range of at least 65536 in
both `/etc/subuid` and `/etc/subgid`; `make doctor` checks this. Never run Make
with sudo. Enable systemd and cgroup delegation in WSL if resource limits fail.

## First sandbox

```bash
make init
nano ~/.config/t3-sandbox/profiles/default.yaml
make doctor
make build
make start
make status
make pair
```

Set `project.directory` to your project. By default a missing project directory
is created; set `project.create_if_missing: false` to require an existing one.
Configuration is YAML data. Paths support `~` and `${HOME}` expansion. The
commented [default profile](config/profile.default.yaml) documents every field.
The default profile is also initialized automatically by configuration commands.

Every Make command selects `PROFILE=default` unless you supply another name.
`PROFILE_DIR=/absolute/path` selects a different profile directory. Configuration
comes exclusively from the selected YAML file; legacy `.env` and `SANDBOX`
settings are no longer read. Existing `.env` files and old Podman resources are
left in place; migrate their settings manually into a profile.

T3 listens on container port 3773. The default host bind is `0.0.0.0:3773`, which
can expose the service beyond localhost according to WSL/network firewall
settings. Set `server.bind_address: 127.0.0.1` to limit it to host loopback.
`make pair` preserves the token and rewrites the address to a usable host route;
wildcard binds use `127.0.0.1` (IPv6 `::` uses `::1`). Set
`server.advertised_url` when clients need another address, for example an HTTPS
reverse proxy. Paste the pairing URL into the T3 desktop app's **Settings →
Connections → Add environment**, and choose `/workspace` for the project.
Pairing links expire and are single-use. Check `make logs` if startup fails.
Windows clients normally use WSL localhost forwarding.

## State and authentication

Each profile keeps its home in
`~/.local/share/t3-sandbox/<profile>/home`. These are ordinary host directories,
not Podman volumes. Recreation and removal retain them and the project. The
launcher never copies state, recursively changes ownership, or removes T3 locks.
Runtime management files and logs live beside the home and cannot be mounted
through the selected project or state directories.

The `default` profile shares the original host `~/.t3` by default. Other profiles
use private T3 state. `state.share_host_provider_state` independently controls
sharing `~/.codex` and `~/.claude` and defaults to true. The three source paths
are configurable under `state`; missing selected state directories are created.
Disabling sharing reveals any private state already in the persistent home.
Shared credentials and files can be changed or deleted by container processes.
Host SSH agents, OS keyrings and `~/.claude.json` are not mounted.

A shared `.t3` contains the database, pairing credentials and environment identity.
Use it with one T3 server at a time. Stop the host server before starting the
default container, or set `state.share_host_t3_state: false` and recreate. The
launcher checks active managed containers' actual mounts and live host runtime
records. T3's own lifetime lock remains authoritative for races; never delete a
lock to work around an active server. Stored host project paths do not become
`/workspace` automatically; register the project inside the container if needed.

For private provider credentials, disable provider sharing and authenticate:

```bash
make exec CMD='codex login --device-auth'
make exec CMD='claude auth login'
make exec CMD='gh auth login'
```

Open the displayed URLs in your normal browser. Use `make shell` for interactive
flows. For API keys, create a private file outside the mounted project:

```bash
install -m 600 /dev/null ~/.config/t3-sandbox/default.env
nano ~/.config/t3-sandbox/default.env
```

Set `runtime.env_file: ~/.config/t3-sandbox/default.env` in the profile, then
recreate. It uses Podman's `NAME=value` format without shell expansion. Secrets
enter the container environment, never image build arguments; `make config`
prints only the file path, never its contents.

## Daily use and multiple profiles

```bash
make shell
make exec CMD='git status'
make smoke                        # tools, HTTPS, server and real file ownership
make logs                         # Ctrl-C leaves the container running
make logs FOLLOW=0 TAIL=20
make stop
make start
make restart
make remove                       # retains project and persistent home
make rebuild                      # pull bases and rebuild without cache
make recreate                     # replace container with current image/settings

make init PROFILE=feature-a
nano ~/.config/t3-sandbox/profiles/feature-a.yaml
make build PROFILE=feature-a
make start PROFILE=feature-a
make pair PROFILE=feature-a
make stop PROFILE=feature-a
```

Named initialization reserves port 3773 for `default` and allocates an available
port from 3774 upward. Each profile selects separate containers, images and
persistent homes. Providers remain shared by default; disable sharing for
independent credentials. Sharing a project shares its actual files. Isolation
is per container/environment; T3 threads within an environment share its mounts
and credentials.

Build/rebuild leave existing containers running on their original image. Start
and restart reject changed mounts, ports, resource limits, health checks, env
file path, or network settings until you explicitly recreate. Build selector
and whitelist edits alone do not replace T3. The selected image ID is recorded
separately from the runtime topology. Stop, status, logs and remove can recover
owned resources even when the profile is invalid or missing. No global prune or
state deletion target is provided.

Automatic Podman health timers are disabled by default. Startup checks T3's
local HTTP endpoint and reports immediate exit codes without requiring systemd.
Set `runtime.automatic_healthcheck: true` and recreate if your systemd user
session supports timers. Use `resources.memory: null` and `resources.cpus: null`
to omit those limits; `resources.pids_limit` stays positive.

## Images, tools and isolation

Build selectors under `build` choose the Ubuntu and Node images and the Codex,
Claude and T3 versions. The default Ubuntu selector is `ubuntu:rolling`; choose
`docker.io/library/ubuntu:latest` for LTS. Pin digests and CLI versions for
reproducibility. Make supplies the matching `HOST_USER`, `HOST_UID` and
`HOST_GID` build arguments. Global tools are image-managed; install system
packages in the Dockerfile, then rebuild and recreate. User-installed tools
live in the persistent home and can override image tools on PATH.

The image includes Node.js, npm/pnpm/Yarn/Bun, TypeScript, T3, Codex, Claude,
Python/uv, Go, Rust, JDK/Maven, native compilers and debugging tools, Git/GitHub
CLI, database clients and common terminal tools. Project-specific dependencies
still need their own installation. Use Linux filesystem paths; Windows mounts
may have synthesized permissions and slower operations. Supplementary host
groups are not passed through.

Unrestricted networking is the default (`network.restricted: false`) and needs
only the T3 image/container. It uses
`slirp4netns:allow_host_loopback=false`. This allows outbound internet and can
reach LAN or host services; it is not an egress firewall. Restricted startup
currently fails with an explicit “not implemented” message while the proxy
implementation is developed. It never falls back to unrestricted networking.
The restricted-mode compiler currently supports only IPv4 external subnets and
DNS resolvers, and rejects IPv6 or mixed operational topology. IPv6-only
resolvers and upstream services are unavailable in this version. IPv6
allowlist parsing and protection of IPv6 host, private, and mapped addresses
remain enabled; this does not provide IPv6 egress support.

The container drops all capabilities, enables `no-new-privileges`, uses private
PID/IPC namespaces and keeps default seccomp. It receives no engine or host
namespace sockets and no network administration capability. Agents can modify
mounted files and send accessible data over allowed network paths. Containers
share the host kernel; use a separate VM for deliberately hostile code.

Some nested browser/provider sandboxes depend on host kernel policies. Do not
resolve failures with privileged mode or host sockets. T3's browser opt-out is
`T3CODE_SERVER_BROWSER_SANDBOX=0` in the runtime env file; this reduces browser
isolation and is not enabled by default.
