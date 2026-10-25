# T3 Code in rootless Podman on WSL2

Run T3, Codex, Claude Code and their terminal processes in a rootless container.
The selected project is mounted read/write at `/workspace`. The container uses
`--userns=keep-id` and your Linux UID/GID, so files it creates belong to you.

Install the host prerequisites inside WSL2 as your ordinary Linux user:

```bash
sudo apt update
sudo apt install -y podman uidmap slirp4netns fuse-overlayfs make python3 curl
podman info --format '{{.Host.Security.Rootless}}' # must print true
```

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) as your
ordinary user if it is not already available:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Ensure `uv` is on your `PATH` (restart your shell after installation).
`make init` creates a repo-local `.venv` and installs the dependencies pinned in
`uv.lock`. Python 3.11 or newer is required; uv can download a compatible Python
if needed. Python packages are installed only in `.venv`, leaving system Python
unchanged. `make python-env` syncs this environment without creating a profile.
The launcher and test targets use `uv run --locked`, so no manual activation is
needed; they also create or update the environment when necessary.

Rootless Podman needs a free, nonoverlapping subordinate ID range of at least 65536 in
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

T3 listens on container port 3773. The default host bind is `0.0.0.0:3774`; host
port 3773 is left free for a T3 UI running on the host (for example on Windows),
which WSL port probes cannot detect. This bind can expose the service beyond
localhost according to WSL/network firewall settings. Set
`server.bind_address: 127.0.0.1` to limit it to host loopback.
`make pair` preserves the token and rewrites the address to a usable host route;
wildcard binds use `127.0.0.1` (IPv6 `::` uses `::1`). Set
`server.advertised_url` when clients need another address, for example an HTTPS
reverse proxy. Paste the pairing URL into the T3 desktop app's **Settings →
Connections → Add environment**, and choose `/workspace` for the project.
Pairing links expire and are single-use. Check `make logs` if startup fails.
Windows clients normally use WSL localhost forwarding.

To customize the host name shown in T3 Code, set `runtime.hostname` in your
profile YAML:

```yaml
runtime:
  hostname: my-dev-host
```

Use a DNS hostname with letters, digits, and hyphens (dot-separated labels are
also supported). Omit the setting or use `null` to keep the generated
`t3-sandbox-<uid>-<profile>` name. Apply changes with
`make recreate PROFILE=<profile>`; rebuilding the image is unnecessary.

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
launcher checks active managed containers' actual mounts and probes T3's existing
SQLite lifetime lock before new or stopped shared-state launches. Container PID
records do not establish host ownership. T3's lock remains authoritative for races; never delete a
lock to work around an active server. Stored host project paths do not become
`/workspace` automatically; register the project inside the container if needed.

For private provider credentials, disable provider sharing and authenticate:

```bash
make exec CMD='codex login --device-auth'
make exec CMD='claude auth login'
make exec CMD='gh auth login'
```

Open the displayed URLs in your normal browser. For Claude subscriptions, run
`make exec CMD='claude auth login'` from an interactive terminal and sign in with
your Claude account. If the browser displays a code instead of completing the
local callback, paste it into the waiting terminal. This is Claude's
[documented headless login flow](https://code.claude.com/docs/en/authentication#log-in-to-claude-code);
its CLI does not document a `--device-auth` flag. You can check the result with
`make exec CMD='claude auth status'`. Credentials saved inside the container
persist in the provider state directories described above.

An `ANTHROPIC_API_KEY` can take precedence over your Claude subscription; remove
it from the container environment when using subscription authentication.
Use `make shell` for other interactive flows.
For API keys, create a private file outside the mounted project:

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
make proxy-restart PROFILE=work    # apply saved allowlist; T3 keeps running
make firewall-logs PROFILE=work    # latest 100 policy denials, then follow
make firewall-logs PROFILE=work FOLLOW=0 TAIL=100  # finite JSONL output
make stop
make start
make restart
make remove                       # retains project and persistent home
make rebuild                      # pull bases and rebuild without cache using latest T3
make recreate                     # replace container with current image/settings

make init PROFILE=feature-a
nano ~/.config/t3-sandbox/profiles/feature-a.yaml
make build PROFILE=feature-a
make start PROFILE=feature-a
make pair PROFILE=feature-a
make stop PROFILE=feature-a
```

`make rebuild` always installs the latest published T3 release, overriding
`build.t3_version` for that build without changing the profile. `make build`
honors the configured version. Run `make recreate` after rebuilding to use the
new image in the container.

Named initialization never allocates host port 3773 (host T3 UI), reserves 3774
for `default`, and allocates an available port from 3775 upward. Each profile selects separate containers, images and
persistent homes. Providers remain shared by default; disable sharing for
independent credentials. Sharing a project shares its actual files. Isolation
is per container/environment; T3 threads within an environment share its mounts
and credentials.

Build/rebuild leave existing containers running on their original image. Start
and restart reject changed mounts, ports, resource limits, health checks, env
file path, or network settings until you explicitly recreate. Build selector
and whitelist edits alone do not replace T3. The selected image ID is recorded
separately from the runtime topology. Stop, status, logs, firewall-logs and remove
can recover owned resources even when the profile is invalid or missing. Status
shows the running gateway readiness digest separately from the saved YAML policy
digest; an unavailable gateway or invalid saved policy is reported explicitly. No global prune or
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

T3's native release and its required sidecar files are installed under
`/opt/t3-runtime`. During the image build, an isolated local T3 server invokes
that release's own pinned browser installer. The build first initializes an
MCP session; releases requiring agent thread scope use the authenticated local
`preview.open` WebSocket RPC instead. Generated credentials and server state
are removed within the same build layer. Unsupported interfaces fail the build.

Browser files and their version/hash manifest live in `/opt/t3-browser`.
Startup verifies them locally and seeds an executable wrapper into a writable
tmpfs at `~/.t3/tools/chrome-headless-shell`. This shadows only the rebuildable
browser cache, preserving shared host browser files and the rest of the home.
No browser or T3 runtime download is needed at startup, including with an empty
home. A missing tmpfs or mismatched image assets stops startup before T3 runs.

Restricted mode supplies both uppercase and lowercase HTTP/HTTPS/ALL proxy
variables after the env file, loopback-only NO_PROXY, and Node 24's
`NODE_USE_ENV_PROXY=1`. The browser wrapper uses Chromium's explicit HTTP proxy
switch and keeps in-container loopback pages reachable. `T3_SANDBOX_BROWSER_PROXY`
is launcher-owned; an env file cannot change it. Clients ignoring proxy settings
remain subject to the network boundary. No browser sandbox-disabling flag is
added automatically.

Unrestricted networking is the default (`network.restricted: false`) and needs
only the T3 image/container. It uses
`slirp4netns:allow_host_loopback=false`. This allows outbound internet and can
reach LAN or host services; it is not an egress firewall. To select restricted mode, set `network.restricted: true` in the profile YAML,
configure `network.allow`, then run `make build PROFILE=work` and
`make start PROFILE=work`. Switching modes requires `make recreate PROFILE=work`.
Restricted mode requires local rootless Podman with Netavark; Podman 4.9.3 /
Netavark 1.4.0 is the verified baseline. Unsupported controls fail closed.

Restricted T3 joins only an internal network with DNS disabled and no default
route. A separate gateway publishes the management port, proxies permitted
outbound traffic on private port 3128, and has forwarding disabled. The launcher
disables host-side private bridge IPv6, rejects an IPv4-addressed bridge, verifies
live routes with a trusted disposable probe, and verifies gateway readiness
before starting T3. The proxy port is never published. Removing proxy variables
does not grant T3 direct internet, host or LAN access.

Runtime policy and topology snapshots live outside T3 mounts in the profile's
`runtime` directory; gateway denial logs live in its separate `logs` directory.
The gateway receives only its read-only policy directory and its logs. Start
checks actual image IDs, mounts, ports and network memberships before reuse.
Topology changes require `make recreate`. Apply saved allowlist edits with
`make proxy-restart PROFILE=work`: the candidate is validated using the existing
gateway image before its policy is published atomically and only that gateway
is restarted. T3 keeps its identity, process, mounts and private address. Active
management and outbound streams must reconnect during the brief interruption.
Invalid candidates leave the running gateway untouched. A failed replacement
leaves the gateway unavailable, with the candidate retained and no policy
rollback or unrestricted fallback; fix the policy and retry `make proxy-restart`.

`make firewall-logs PROFILE=work` prints normalized denial JSONL records from only
the selected profile, showing the latest 100 records across retained files and
following rotation and gateway restarts. Use `FOLLOW=0 TAIL=100` for finite output
in chronological file order; selectors do not modify YAML. Ctrl-C stops viewing
and leaves containers running. Diagnostics use stderr. This is a proxy-policy
log: direct attempts that fail locally because T3 has no route never reach it.
Stop shuts down T3 before the gateway. Remove preserves persistent homes and logs.
Restricted mode never falls back to unrestricted networking.
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

## Manual migration from `.env` and named home volumes

Normal commands neither import legacy settings nor copy or delete legacy volumes.
Initialize the selected profile, inspect its YAML, and translate values manually:

| Legacy setting | Profile field or action |
| --- | --- |
| `SANDBOX` | Select `PROFILE=<name>` on every Make command |
| `PROJECT_DIR` | `project.directory` |
| `HOST_PORT` | `server.port`; select `server.bind_address` explicitly |
| `SHARE_HOST_STATE` | `state.share_host_provider_state`; choose T3 sharing independently |
| `SHARE_HOST_T3_STATE` | `state.share_host_t3_state` |
| `HOST_T3_DIR`, `HOST_CODEX_DIR`, `HOST_CLAUDE_DIR` | Corresponding `state.*_directory` |
| `UBUNTU_IMAGE`, `NODE_IMAGE` | `build.ubuntu_image`, `build.node_image` |
| `CODEX_VERSION`, `CLAUDE_VERSION`, `T3_VERSION` | Corresponding `build.*_version` |
| `MEMORY`, `CPUS`, `PIDS_LIMIT` | Corresponding `resources` fields; use YAML `null` to omit memory/CPU limits |
| `AUTO_HEALTHCHECK` | `runtime.automatic_healthcheck` as YAML `true`/`false` |
| `RUNTIME_ENV_FILE` | `runtime.env_file` |
| `IMAGE` | No image override; images are derived from UID/profile and built from `build` selectors |

The old `SHARE_HOST_STATE=0` disabled all sharing; translate that intent by
setting both sharing flags to false. Strings such as `"0"` are not YAML booleans.
Legacy profiles bound loopback; explicitly use `127.0.0.1` to retain that exposure.

Copy a legacy private home only while **both old and new T3 servers are stopped**.
First run `podman ps -a` and `podman volume inspect <exact-legacy-volume>`.
Inspect the old container's mounts to distinguish the private home volume from
host `.t3`/provider bind mounts: bind-mounted contents are not in that volume.
The historical name was `t3-sandbox-<uid>-<SANDBOX>-home`; confirm it instead of
guessing. Record its mountpoint, ownership and contents, and take an offline
backup before changing anything. Do not remove database lock files.

For a private-state destination, set both sharing flags false and initialize
the profile without starting it. The following is a template for an **empty**
destination; substitute reviewed absolute paths and the inspected exact volume:

```bash
podman volume inspect t3-sandbox-1000-main-home
podman unshare ls -lan /absolute/inspected/volume/_data
install -d -m 700 ~/.local/share/t3-sandbox/migrated/home
# Inspect this directory; stop if it already contains state.
ls -la ~/.local/share/t3-sandbox/migrated/home
umask 077
legacy_backup=$(mktemp /tmp/t3-legacy-home.XXXXXXXX)
podman unshare tar -C /absolute/inspected/volume/_data -cpf "$legacy_backup" .
# The backup may contain credentials: protect it and retain it offline.
chmod 600 "$legacy_backup"
podman unshare tar --no-same-owner -C ~/.local/share/t3-sandbox/migrated/home -xpf "$legacy_backup"
```

Rootless namespace root may map to your host user, while legacy workload files
may have subordinate-ID ownership. Inspect the copied files as your ordinary
user before starting; if inaccessible, stop and plan an explicit ownership
conversion for only the copied destination. No automatic recursive chown is
performed. Review old absolute paths and provider files before use. Build/start
the new profile and verify its data; keep the original volume and backup until
you have independently validated the migration. No volume deletion is required.

## Verification and operating limits

`make test` runs unit tests only. `T3_SANDBOX_INTEGRATION=1 make test-integration`
builds images and runs real Podman tests with random `it-*` profiles, temporary
homes and explicit cleanup; it needs the documented host prerequisites and
internet access for permitted HTTPS controls. See
[network verification](docs/network-verification.md) for coverage and limitations.
`make smoke` checks local and published T3 readiness and project file ownership;
restricted mode probes provider HTTPS, accepting an expected unauthenticated
401/403, and does not contact npm.

Mutating commands serialize on a per-profile lock outside removable runtime
files. Separate profiles can operate concurrently. Never run two servers over
one shared `.t3`. Allowlist edits require `proxy-restart`; changing structural
settings requires `recreate`. Set `network.restricted: false`, then recreate to
disable enforcement explicitly.

A wildcard bind controls listening, while `server.advertised_url` controls the
pairing URL; advertising an address does not open WSL/Windows/host firewalls or
configure routing/TLS. Remote clients require separately configured forwarding
and firewall rules. A successful host non-loopback check does not establish
reachability from another physical device.

Destination grants permit data transfer to that destination. HTTPS is tunneled
without TLS interception, so grants do not restrict URL paths or content.
The host, kernel, container engine and trusted gateway remain in the trust
boundary. Proxy denial logs exclude direct local routing failures and upstream
application 403 responses; they are not a complete traffic audit.
