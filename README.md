# T3 Code in rootless Podman on WSL2

Run the T3 server, Codex, Claude Code, and their terminal processes inside one
container. A selected host directory is mounted read/write at `/workspace`.
The container runs as your Linux username with the same numeric UID/GID using
Podman's `--userns=keep-id`; files it creates belong to your WSL user.
By default, the host user's `.t3`, `.codex`, and `.claude` directories are also
mounted read/write at the matching locations inside the container home.

The default base is `ubuntu:rolling`, which tracks the newest stable Ubuntu
release (26.10 at the time of writing). `ubuntu:latest` tracks the newest **LTS**
instead. Set `UBUNTU_IMAGE=docker.io/library/ubuntu:latest` if you prefer LTS.
See the [official Ubuntu image documentation](https://hub.docker.com/_/ubuntu).

## WSL prerequisites

Run these commands inside your WSL2 distribution as the user who will own the
projects, for example `tobias2`. Use the Linux Podman package inside WSL, rather
than a remote Podman machine or Docker Desktop connection.

```bash
sudo apt update
sudo apt install -y podman uidmap slirp4netns fuse-overlayfs make python3 python3-yaml curl
podman info --format '{{.Host.Security.Rootless}}'  # must print true
```

The YAML profile loader requires distribution PyYAML (`sudo apt install python3-yaml`).
Use the distribution Python interpreter, `/usr/bin/python3`, if a pyenv or virtual
environment shadows `python3`; the loader never installs host dependencies.

Rootless Podman needs subordinate UID and GID ranges in `/etc/subuid` and
`/etc/subgid`. Distribution packages usually arrange this for ordinary users.
`make doctor` checks it. If missing, have an administrator assign a **free,
nonoverlapping** range of at least 65536 IDs to your user in both files, then run
`podman system migrate` as that user. Do not reuse another account's range.
Never run this Makefile with `sudo`.

Enable systemd in WSL if rootless cgroup/resource-limit errors occur: add
`[boot]` followed by `systemd=true` to `/etc/wsl.conf`, then run `wsl --shutdown`
from Windows PowerShell and reopen WSL. This stops all running WSL distributions.
The optional CPU/memory limits require functioning cgroup delegation; setting
`CPUS=` and `MEMORY=` omits those two limits.

Automatic Podman health-check timers need a working systemd user session and are
disabled by default (`AUTO_HEALTHCHECK=0`). Startup checks T3's HTTP endpoint
directly and reports an early container exit; `make smoke` also works without
systemd. Set `AUTO_HEALTHCHECK=1` and recreate if you want automatic health status
and have a working user session. Removing an older container may still print a
timer-removal warning from its previous configuration.

## First sandbox

```bash
make init
# Edit .env: set PROJECT_DIR to your existing project directory.
# Quote paths with spaces. ${HOME} expands to the current WSL user's home.
nano .env
make doctor
make build
make start
make status
make pair
```

Paste the URL printed by `make pair` into **Settings → Connections → Add
environment** in the T3 desktop app. Choose `/workspace` when adding the project
inside that environment. Pairing links expire and are single-use; run `make pair`
again for another client. If T3 is still starting, check `make logs` and retry.

T3 listens on `0.0.0.0:3773` **inside** the container. Podman publishes it only on
`127.0.0.1:HOST_PORT` in WSL. The helper rewrites the advertised container address
to this host endpoint while preserving the pairing token in the URL fragment.
Use this rewritten link, since startup logs contain the internal address.
Windows normally reaches this through WSL localhost forwarding; verify
`http://localhost:3773` in Windows if using the Windows desktop app. Custom WSL
networking/firewall settings can affect forwarding. This setup does not expose
T3 to your LAN. The hosted HTTPS web client may require an HTTPS backend; prefer
the desktop app for this localhost HTTP setup.

## Authentication

The default configuration reuses your host's T3, Codex, and Claude directories:

```bash
# In .env (also the defaults when these settings are omitted):
SHARE_HOST_STATE=1
HOST_T3_DIR="${HOME}/.t3"
HOST_CODEX_DIR="${HOME}/.codex"
HOST_CLAUDE_DIR="${HOME}/.claude"

# Create any missing directories, then apply mounts to an existing container:
mkdir -p ~/.t3 ~/.codex ~/.claude
make recreate
```

No image rebuild is needed. The directories appear as
`/home/<your-user>/.t3`, `.codex`, and `.claude`, overlaid on the private home
volume. Changes, credentials, and deletions in them affect the host directories.
The launcher preserves ownership and does not copy or migrate existing state.
Old private state remains in the home volume, hidden by the bind mounts; set
`SHARE_HOST_STATE=0` and recreate to use that private state again.

Sharing `.t3` shares the full database, pairing credentials, and environment
identity. Use a shared `.t3` directory with **one T3 server at a time**; stop the
host server before starting this container. For multiple independent containers,
use separate state directories or `SHARE_HOST_STATE=0` rather than pointing all
servers at the same `.t3` directory. Stored project paths must exist inside the
container: host paths do not automatically become `/workspace`. Register the
mounted repository with `make exec CMD='t3 project add /workspace'` if needed.

To keep the host T3 server running while sharing Codex and Claude state, set
`SHARE_HOST_T3_STATE=0` in `.env`, then `make recreate`. This leaves `.t3` in the
container's private home volume and continues to bind-mount `.codex` and
`.claude`. Pair the container as a separate environment with `make pair`.
If logs show `ServerAlreadyRunningError`, another server owns the selected T3
state directory; restarting repeatedly or deleting its lock is not a remedy.

Only the three directories are shared. Host SSH agents, OS keyrings, and
`~/.claude.json` are not mounted. If a provider still requests login, authenticate
inside the container. With `SHARE_HOST_STATE=0`, authenticate each sandbox
separately:

```bash
make exec CMD='codex login --device-auth'
make exec CMD='claude auth login'
make exec CMD='gh auth login'
```

Open the displayed login URLs/codes on your normal browser. If your Claude login
flow requires an interactive session, use `make shell`, run `claude`, and follow
its sign-in prompts. Codex device login must be enabled for your account.
Credentials and T3 data persist in the host directories when sharing is enabled,
or in that sandbox's private home volume otherwise.

For API keys instead, create a private file **outside the mounted project**:

```bash
mkdir -p ~/.config/t3-sandbox
install -m 600 /dev/null ~/.config/t3-sandbox/main.env
nano ~/.config/t3-sandbox/main.env
# OPENAI_API_KEY=...
# ANTHROPIC_API_KEY=...
```

Set `RUNTIME_ENV_FILE="${HOME}/.config/t3-sandbox/main.env"` in `.env` and run
`make recreate`. This file uses Podman's `NAME=value` format, without shell
expansion. Keys enter the container environment and are accessible to its
processes and to the host account managing Podman. Nothing passes through build
arguments. `.env` itself is trusted Bash configuration; do not source untrusted
copies.

## Daily use and updates

```bash
make shell                         # bash at /workspace
make exec CMD='git status'
make smoke                         # tools, HTTPS, server, real host file ownership
make logs                          # Ctrl-C stops following, not the server
make stop
make start                         # reuse same container and state
make restart                       # restart existing container
make remove                        # remove container, keep project and home volume

make rebuild                       # refresh bases/packages/CLIs, no build cache
make recreate                      # replace container with newly built image
```

`build` and `rebuild` do not replace a running container. `restart` reuses its
original image and settings; use `recreate` to apply a new image, project path,
port, state mount, resource limit, or runtime environment file. Files outside `/workspace`
and the container home disappear on recreation. Agent-created files in the
project and home survive. The Makefile deliberately has no volume deletion or
global prune target; private home volumes contain login credentials and T3
history. To erase a sandbox completely, first remove its container, inspect the
volume name with `make config`, then explicitly remove that volume yourself.

Global tools are image-managed; Claude background updates are disabled. Install
extra system packages in `Dockerfile` and rebuild. For user tools use `uv tool
install`, `pipx`, or `npm install -g` (its prefix is in the persistent home).
User-installed executables can override image tools on PATH. Use a Python venv
for project dependencies; Ubuntu's system Python is externally managed.

## Multiple isolated environments

Use a unique sandbox name and free host port for each environment:

```bash
make start SANDBOX=feature-a HOST_PORT=3774 PROJECT_DIR="$HOME/projects/feature-a"
make pair SANDBOX=feature-a HOST_PORT=3774
make shell SANDBOX=feature-a
make stop SANDBOX=feature-a

make start SANDBOX=feature-b HOST_PORT=3775 PROJECT_DIR="$HOME/projects/feature-b"
make pair SANDBOX=feature-b HOST_PORT=3775
```

Environment and `make` command-line settings override `.env`. Each name selects
a separate container and home volume; images are shared for the same host user.
The default host state mounts are shared across those containers. Set
`SHARE_HOST_STATE=0` in `.env` for the independent environments in these examples.
Use separate project directories/clones when you also want to isolate changes.
Sharing a project directory shares the actual files. This provides isolation
**per environment/container**, not automatically per T3 thread: threads created
inside one environment share its container, mounted project, and credentials.
Use one container/environment for each thread that needs that boundary.

## Included tools

- Node.js 24, npm, pnpm, Yarn, Bun, TypeScript, tsx; T3 Code and Codex via npm.
- Claude Code via its native installer.
- Python 3, pip/venv/pipx, uv/uvx; Go; Rust/Cargo; JDK and Maven.
- GCC/G++, Clang, Make, CMake, Ninja, pkg-config, GDB, strace, common native headers.
- Git, Git LFS, GitHub CLI, SSH client, curl/wget, jq, ripgrep, fd-find, fzf.
- SQLite, PostgreSQL client, editors, tmux, archive/network/process tools.
- Common Chromium runtime libraries. Browser binaries may download on first use.

This is a broad coding baseline; project-specific SDKs and services still need
their own dependencies. `fd-find` uses Ubuntu's `fdfind` executable name. The
Dockerfile supports amd64 and arm64 through its upstream images/installers.

Build-time selectors are in `.env.example`: `UBUNTU_IMAGE`, `NODE_IMAGE`,
`CODEX_VERSION`, `CLAUDE_VERSION`, `T3_VERSION`. For reproducibility, pin image
digests and CLI versions; floating tags update on `make rebuild`. Building the
Dockerfile directly requires passing `HOST_USER`, `HOST_UID`, and `HOST_GID` for
the intended user; `make build` does this automatically.

## Isolation and permissions

The launcher explicitly uses a rootless user namespace, the matching non-root
user, private process/IPC namespaces, no Linux capabilities, and
`no-new-privileges`. Default Podman seccomp remains enabled. Host bind mounts
include the selected project and, by default, the three configured T3/provider
state directories. The rest of the container home is a Podman named volume.
Host SSH agents, Windows drives, and container-engine sockets are not mounted.
No `:U`, recursive `chown`, or permission rewrites are applied to host mounts.
See [Podman's user namespace and volume options](https://docs.podman.io/en/stable/markdown/podman-run.1.html#userns-mode).

Use a directory owned by your WSL user on the Linux filesystem (`/home/...`).
Windows mounts such as `/mnt/c/...` may have synthesized permissions and slower
file operations; matching UID/GID cannot fix their filesystem semantics.
Primary group ownership is preserved. Supplementary host groups are not passed
through, so group-only access to another user's project may need an explicit
ACL or ownership arrangement outside this setup.

Outbound networking, including DNS/HTTPS, is enabled through slirp4netns.
`allow_host_loopback=false` blocks its special host-loopback route, but is not an
egress firewall: reachable LAN/host addresses and services may still be accessed.
Agents can modify/delete mounted project files and send accessible data over
the network. Keep secrets outside that directory. Linux containers share WSL's
kernel; use a separate VM for deliberately hostile code.

T3's browser sandbox or providers' nested sandboxes can require kernel features
restricted by the host's AppArmor/user-namespace policies. Do not resolve this
with privileged mode or host sockets. If T3 reports a browser sandbox failure,
its documented opt-out is `T3CODE_SERVER_BROWSER_SANDBOX=0` in the runtime env
file, then `make recreate`; this disables only the browser's inner sandbox and
reduces browser isolation. It is not enabled by default. See
[T3 remote/browser setup](https://github.com/pingdotgg/t3code/blob/main/docs/user/remote-access.md).

Installation references: [Codex CLI](https://developers.openai.com/codex/cli/),
[Claude Code setup](https://code.claude.com/docs/en/setup),
[T3 server package](https://github.com/pingdotgg/t3code/blob/main/apps/server/package.json).
