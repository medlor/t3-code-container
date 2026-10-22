# rolling = latest stable Ubuntu release; latest = latest Ubuntu LTS.
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:rolling
ARG NODE_IMAGE=docker.io/library/node:24-bookworm-slim
FROM ${NODE_IMAGE} AS node
FROM ghcr.io/astral-sh/uv:latest AS uv
FROM ${UBUNTU_IMAGE}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8

# No sudo, container engine, host sockets, or host credentials in this image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget gnupg openssh-client git git-lfs gh \
    build-essential clang cmake ninja-build pkg-config gdb strace \
    python3 python3-dev python3-pip python3-venv pipx \
    golang-go rustc cargo default-jdk-headless maven \
    sqlite3 libsqlite3-dev libssl-dev libffi-dev postgresql-client \
    bash-completion zsh tmux vim nano less file tree unzip zip xz-utils \
    jq ripgrep fd-find fzf shellcheck iproute2 iputils-ping dnsutils procps psmisc \
    libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2t64 libpango-1.0-0 libcairo2 fonts-liberation \
    && git lfs install --system \
    && rm -rf /var/lib/apt/lists/*

# Copy Node's runtime only, without replacing Ubuntu's system libraries.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=uv /uv /uvx /usr/local/bin/

ARG CODEX_VERSION=latest
ARG T3_VERSION=latest
ARG CLAUDE_VERSION=latest
RUN npm install -g --allow-scripts=bun,pnpm,yarn,esbuild \
    "@openai/codex@${CODEX_VERSION}" "t3@${T3_VERSION}" \
    pnpm yarn bun typescript tsx \
    && npm cache clean --force
# Use Claude's native installer; copy its actual executable outside /root.
RUN curl -fsSL https://claude.ai/install.sh -o /tmp/install-claude.sh \
    && bash /tmp/install-claude.sh "${CLAUDE_VERSION}" \
    && install -m 0755 "$(readlink -f /root/.local/bin/claude)" /usr/local/bin/claude \
    && rm -rf /root/.claude /root/.local /tmp/install-claude.sh

# Drive this installed T3 release's own pinned installer in disposable state.
# Helper removes the entire temporary HOME/database/auth state in this RUN layer.
COPY scripts/t3_sandbox/__init__.py scripts/t3_sandbox/browser.py /usr/local/lib/t3-sandbox/t3_sandbox/
COPY scripts/install-t3-browser.py /usr/local/lib/t3-sandbox/install-t3-browser.py
COPY --chmod=755 scripts/browser-launcher.sh /usr/local/libexec/t3-browser-launcher
RUN python3 /usr/local/lib/t3-sandbox/install-t3-browser.py \
    --t3 /usr/local/bin/t3 --destination /opt/t3-browser
COPY scripts/t3_sandbox/browser.py /usr/local/lib/t3-sandbox/browser.py

ARG HOST_USER=developer
ARG HOST_UID=1000
ARG HOST_GID=1000
# Ubuntu images can already have an ubuntu account occupying UID 1000.
RUN if getent passwd "${HOST_UID}" >/dev/null; then \
      userdel --remove "$(getent passwd "${HOST_UID}" | cut -d: -f1)"; \
    fi \
    && if ! getent group "${HOST_GID}" >/dev/null; then \
      groupadd --gid "${HOST_GID}" "${HOST_USER}"; \
    fi \
    && useradd --uid "${HOST_UID}" --gid "${HOST_GID}" --create-home \
      --shell /bin/bash "${HOST_USER}" \
    && mkdir -p /workspace \
    && chown "${HOST_UID}:${HOST_GID}" /workspace
LABEL io.t3-sandbox.uid="${HOST_UID}" io.t3-sandbox.gid="${HOST_GID}" \
      io.t3-sandbox.user="${HOST_USER}"

ENV HOME=/home/${HOST_USER} \
    PATH=/home/${HOST_USER}/.local/bin:/home/${HOST_USER}/.npm-global/bin:${PATH} \
    NPM_CONFIG_PREFIX=/home/${HOST_USER}/.npm-global \
    DISABLE_AUTOUPDATER=1
COPY --chmod=755 scripts/entrypoint.sh /usr/local/bin/sandbox-entrypoint
USER ${HOST_UID}:${HOST_GID}
WORKDIR /workspace
RUN node --version && codex --version && claude --version && t3 --version \
    && bun --version && pnpm --version && yarn --version && uv --version
EXPOSE 3773
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=4 \
    CMD curl --silent --output /dev/null --fail http://127.0.0.1:3773/ || exit 1
ENTRYPOINT ["sandbox-entrypoint"]
CMD ["t3", "serve", "--host", "0.0.0.0", "--port", "3773", "--no-browser"]
