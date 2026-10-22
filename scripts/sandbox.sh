#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

# Preserve explicit environment/make overrides when loading the local config.
settings=(PROJECT_DIR SANDBOX HOST_PORT IMAGE UBUNTU_IMAGE NODE_IMAGE CODEX_VERSION
    CLAUDE_VERSION T3_VERSION MEMORY CPUS PIDS_LIMIT RUNTIME_ENV_FILE
    SHARE_HOST_STATE SHARE_HOST_T3_STATE HOST_T3_DIR HOST_CODEX_DIR HOST_CLAUDE_DIR
    AUTO_HEALTHCHECK)
declare -A overrides=()
for setting in "${settings[@]}"; do
    if [[ -v $setting ]]; then overrides[$setting]=${!setting}; fi
done
if [[ -f .env ]]; then
    # shellcheck source=/dev/null
    source .env
fi
for setting in "${!overrides[@]}"; do printf -v "$setting" '%s' "${overrides[$setting]}"; done

HOST_UID=$(id -u)
HOST_GID=$(id -g)
HOST_USER=$(id -un)
: "${SANDBOX:=main}" "${HOST_PORT:=3773}" "${IMAGE:=localhost/t3-code-sandbox:${HOST_UID}}"
: "${UBUNTU_IMAGE:=docker.io/library/ubuntu:rolling}" "${NODE_IMAGE:=docker.io/library/node:24-bookworm-slim}"
: "${CODEX_VERSION:=latest}" "${CLAUDE_VERSION:=latest}" "${T3_VERSION:=latest}"
MEMORY=${MEMORY-8g}
CPUS=${CPUS-4}
: "${PIDS_LIMIT:=2048}"
CONTAINER="t3-sandbox-${HOST_UID}-${SANDBOX}"
VOLUME="${CONTAINER}-home"
CONTAINER_HOME="/home/${HOST_USER}"
: "${SHARE_HOST_STATE:=1}" "${HOST_T3_DIR:=$HOME/.t3}"
: "${HOST_CODEX_DIR:=$HOME/.codex}" "${HOST_CLAUDE_DIR:=$HOME/.claude}"
: "${SHARE_HOST_T3_STATE:=1}" "${AUTO_HEALTHCHECK:=0}"
state_args=()
state_signature=private

die() { echo "Error: $*" >&2; exit 1; }
[[ $SANDBOX =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || die 'SANDBOX must contain only letters, digits, _, . and -.'
if ! [[ $HOST_PORT =~ ^[0-9]+$ ]] || ! (( 10#$HOST_PORT >= 1024 && 10#$HOST_PORT <= 65535 )); then
    die 'HOST_PORT must be 1024..65535.'
fi
[[ $HOST_USER =~ ^[a-z_][a-z0-9_-]*$ ]] || die 'Unsupported Linux username.'
[[ $SHARE_HOST_STATE == 0 || $SHARE_HOST_STATE == 1 ]] || die 'SHARE_HOST_STATE must be 0 or 1.'
[[ $SHARE_HOST_T3_STATE == 0 || $SHARE_HOST_T3_STATE == 1 ]] || die 'SHARE_HOST_T3_STATE must be 0 or 1.'
[[ $AUTO_HEALTHCHECK == 0 || $AUTO_HEALTHCHECK == 1 ]] || die 'AUTO_HEALTHCHECK must be 0 or 1.'

rootless() {
    [[ $HOST_UID != 0 ]] || die 'Run make as your WSL user, without sudo.'
    command -v podman >/dev/null || die 'Install Podman first; see README.md.'
    [[ $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || die 'A working local rootless Podman is required.'
}
exists() { podman container exists "$CONTAINER"; }
running() { [[ $(podman inspect --format '{{.State.Running}}' "$CONTAINER") == true ]]; }
require_running() {
    if ! exists || ! running; then die 'Start the sandbox first: make start'; fi
}
project() {
    [[ -n ${PROJECT_DIR:-} ]] || die 'Set PROJECT_DIR in .env or on the make command line.'
    [[ -d $PROJECT_DIR ]] || die "PROJECT_DIR does not exist: $PROJECT_DIR"
    PROJECT_DIR=$(realpath -- "$PROJECT_DIR")
    [[ $PROJECT_DIR != / && $PROJECT_DIR != "$HOME" ]] || die 'Choose a dedicated project directory, not / or your entire home.'
    [[ $PROJECT_DIR != *','* && $PROJECT_DIR != *$'\n'* ]] || die 'Project path cannot contain commas or newlines.'
    [[ -w $PROJECT_DIR ]] || die "Project is not writable by $HOST_USER: $PROJECT_DIR"
}
state_mounts() {
    state_args=()
    state_signature=private
    [[ $SHARE_HOST_STATE == 1 ]] || return 0
    local setting source destination
    for setting in HOST_T3_DIR HOST_CODEX_DIR HOST_CLAUDE_DIR; do
        if [[ $setting == HOST_T3_DIR && $SHARE_HOST_T3_STATE == 0 ]]; then continue; fi
        source=${!setting}
        [[ -d $source ]] || die "$setting directory does not exist: $source. Create it or set SHARE_HOST_STATE=0."
        source=$(realpath -- "$source")
        [[ $source != *','* && $source != *$'\n'* ]] || die "$setting cannot contain commas or newlines."
        [[ -r $source && -w $source && -x $source ]] || die "$setting must be readable and writable by $HOST_USER: $source"
        case $setting in
            HOST_T3_DIR) destination=.t3 ;;
            HOST_CODEX_DIR) destination=.codex ;;
            HOST_CLAUDE_DIR) destination=.claude ;;
        esac
        state_args+=(--mount "type=bind,src=${source},dst=${CONTAINER_HOME}/${destination}")
    done
    state_signature=$(printf '%s\0' "${state_args[@]}" | sha256sum)
    state_signature=${state_signature%% *}
}
build() {
    local extra=()
    if [[ ${1:-} == fresh ]]; then extra+=(--no-cache); fi
    podman build --format=docker --pull=always "${extra[@]}" -f Dockerfile -t "$IMAGE" \
        --build-arg "UBUNTU_IMAGE=$UBUNTU_IMAGE" --build-arg "NODE_IMAGE=$NODE_IMAGE" \
        --build-arg "HOST_USER=$HOST_USER" --build-arg "HOST_UID=$HOST_UID" --build-arg "HOST_GID=$HOST_GID" \
        --build-arg "CODEX_VERSION=$CODEX_VERSION" --build-arg "CLAUDE_VERSION=$CLAUDE_VERSION" \
        --build-arg "T3_VERSION=$T3_VERSION" "$ROOT"
}
wait_ready() {
    local code deadline
    deadline=$((SECONDS + 30))
    while ((SECONDS < deadline)); do
        if ! running; then
            code=$(podman inspect --format '{{.State.ExitCode}}' "$CONTAINER")
            die "Container exited (code $code). Run make logs for the startup error. A shared .t3 directory requires the host T3 server to be stopped; use SHARE_HOST_T3_STATE=0 for private T3 state."
        fi
        if podman exec "$CONTAINER" curl --fail --silent --noproxy '*' \
            --connect-timeout 1 --max-time 1 --output /dev/null http://127.0.0.1:3773/; then
            return
        fi
        sleep 1
    done
    die 'Container is running, but T3 did not become ready within 30 seconds. Run make logs; startup may still be in progress.'
}
start() {
    project
    state_mounts
    if exists; then
        # Never silently reuse a container pointing at another project/port.
        local mounted published saved_state
        mounted=$(podman inspect --format '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
        published=$(podman inspect --format '{{json .HostConfig.PortBindings}}' "$CONTAINER" | python3 -c \
            'import json, sys; print("\n".join(p["HostIp"] + ":" + p["HostPort"] for p in (json.load(sys.stdin) or {}).get("3773/tcp", [])))')
        [[ $mounted == "$PROJECT_DIR" && $published == "127.0.0.1:$HOST_PORT" ]] || \
            die 'Project or port changed. Run make recreate to apply the new settings.'
        saved_state=$(podman inspect --format '{{index .Config.Labels "io.t3-sandbox.state-mounts"}}' "$CONTAINER")
        if [[ $saved_state != "$state_signature" ]]; then
            # Containers created before shared-state support used a private home.
            [[ -z $saved_state && $SHARE_HOST_STATE == 0 ]] || \
                die 'State mounts changed. Run make recreate to apply the new settings.'
        fi
        if running; then echo "$CONTAINER is already running."; else podman start "$CONTAINER"; fi
        wait_ready
        return
    fi
    podman image exists "$IMAGE" || die 'Build the image first: make build'
    local identity expected
    identity=$(podman image inspect --format '{{index .Labels "io.t3-sandbox.uid"}}:{{index .Labels "io.t3-sandbox.gid"}}:{{index .Labels "io.t3-sandbox.user"}}' "$IMAGE")
    expected="$HOST_UID:$HOST_GID:$HOST_USER"
    [[ $identity == "$expected" ]] || die 'Image was built for another user. Run make build as the current user.'
    local args=(--detach --name "$CONTAINER" --hostname "$CONTAINER"
        --label io.t3-sandbox.managed=true
        --label "io.t3-sandbox.state-mounts=$state_signature"
        --userns=keep-id --user "$HOST_UID:$HOST_GID"
        --cap-drop=all --security-opt=no-new-privileges
        --network=slirp4netns:allow_host_loopback=false
        --pid=private --ipc=private --pids-limit "$PIDS_LIMIT"
        --init --shm-size=512m --stop-timeout=30
        --publish "127.0.0.1:${HOST_PORT}:3773"
        --mount "type=bind,src=${PROJECT_DIR},dst=/workspace"
        --volume "${VOLUME}:${CONTAINER_HOME}"
        --env "HOME=$CONTAINER_HOME" --workdir /workspace)
    args+=("${state_args[@]}")
    if [[ $AUTO_HEALTHCHECK == 0 ]]; then args+=(--no-healthcheck); fi
    [[ -z $MEMORY ]] || args+=(--memory "$MEMORY")
    [[ -z $CPUS ]] || args+=(--cpus "$CPUS")
    if [[ -n ${RUNTIME_ENV_FILE:-} ]]; then
        [[ -f $RUNTIME_ENV_FILE ]] || die "Runtime env file not found: $RUNTIME_ENV_FILE"
        args+=(--env-file "$RUNTIME_ENV_FILE")
    fi
    podman run "${args[@]}" "$IMAGE"
    wait_ready
    echo "T3 endpoint: http://127.0.0.1:$HOST_PORT (ready)"
    echo 'Run make logs for startup details, then make pair for a fresh pairing URL.'
}
stop() { if exists && running; then podman stop "$CONTAINER"; fi; }
remove() { stop; if exists; then podman rm "$CONTAINER"; fi; }
interactive_exec() {
    local args=(-i)
    if [[ -t 0 && -t 1 ]]; then args+=(-t); fi
    podman exec "${args[@]}" "$CONTAINER" "$@"
}

case ${1:-help} in
    init)
        [[ ! -e .env ]] || die '.env already exists; edit it directly.'
        cp .env.example .env
        echo 'Created .env. Set PROJECT_DIR before make start.'
        ;;
    config)
        printf '%s\n' "User: $HOST_USER ($HOST_UID:$HOST_GID)" "Image: $IMAGE" \
            "Container: $CONTAINER" "Home volume: $VOLUME" "Project: ${PROJECT_DIR:-<unset>} -> /workspace" \
            "Port: 127.0.0.1:$HOST_PORT -> 3773" "Ubuntu: $UBUNTU_IMAGE"
        if [[ $SHARE_HOST_STATE == 1 ]]; then
            echo 'Shared state (read/write):'
            if [[ $SHARE_HOST_T3_STATE == 1 ]]; then
                echo "  $HOST_T3_DIR -> $CONTAINER_HOME/.t3"
            else
                echo '  .t3: private container home volume'
            fi
            printf '%s\n' \
                "  $HOST_CODEX_DIR -> $CONTAINER_HOME/.codex" \
                "  $HOST_CLAUDE_DIR -> $CONTAINER_HOME/.claude"
        else
            echo 'State: private container home volume'
        fi
        echo "Automatic health checks: $AUTO_HEALTHCHECK"
        ;;
    doctor)
        rootless
        command -v slirp4netns >/dev/null || die 'Install slirp4netns.'
        command -v newuidmap >/dev/null || die 'Install uidmap.'
        command -v newgidmap >/dev/null || die 'Install uidmap.'
        for file in /etc/subuid /etc/subgid; do
            awk -F: -v name="$HOST_USER" -v uid="$HOST_UID" \
                '($1 == name || $1 == uid) && $3 >= 65536 {ok=1} END {exit !ok}' "$file" || \
                die "Assign $HOST_USER a nonoverlapping subordinate ID range of at least 65536 in $file."
        done
        podman info --format 'Rootless: {{.Host.Security.Rootless}}; cgroups: {{.Host.CgroupsVersion}}'
        [[ -z ${PROJECT_DIR:-} ]] || project
        state_mounts
        echo 'Host prerequisites passed.'
        ;;
    build) rootless; build ;;
    rebuild) rootless; build fresh ;;
    start) rootless; start ;;
    stop) rootless; stop ;;
    restart) rootless; stop; start ;;
    recreate) rootless; project; state_mounts; remove; start ;;
    remove) rootless; remove ;;
    status)
        rootless
        podman ps -a --filter "name=^${CONTAINER}$"
        if exists; then podman port "$CONTAINER"; fi
        ;;
    logs) rootless; podman logs --follow --tail=100 "$CONTAINER" ;;
    shell) rootless; require_running; interactive_exec bash ;;
    exec)
        rootless; require_running
        [[ -n ${CMD:-} ]] || die 'Usage: make exec CMD="codex login --device-auth"'
        interactive_exec bash -c "$CMD"
        ;;
    pair)
        rootless; require_running
        # T3 advertises the container IP; retain the token but use the host route.
        podman exec "$CONTAINER" t3 pair | python3 scripts/pair-url.py "http://127.0.0.1:$HOST_PORT"
        ;;
    smoke)
        rootless; require_running; project
        podman exec "$CONTAINER" bash -ec '
            test "$(id -u)" != 0
            id
            node --version; npm --version; codex --version; claude --version; t3 --version
            python3 --version; uv --version; go version; rustc --version; javac -version
            curl --fail --silent --show-error --output /dev/null https://registry.npmjs.org/
        '
        # Check the real host-visible result of a container write; clean up only our file.
        probe=$(podman exec "$CONTAINER" mktemp /workspace/.t3-permission-check.XXXXXXXX)
        probe="$PROJECT_DIR/${probe##*/}"
        trap 'rm -f -- "$probe"' EXIT
        [[ $(stat -c '%u:%g' -- "$probe") == "$HOST_UID:$HOST_GID" ]] || die 'Host file ownership does not match.'
        curl --silent --show-error --fail --output /dev/null "http://127.0.0.1:$HOST_PORT/"
        echo 'Tools, outbound HTTPS, T3 HTTP, and host UID/GID ownership passed.'
        ;;
    *) die 'Unknown command. Run make help.' ;;
esac
