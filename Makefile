.DEFAULT_GOAL := help
PROFILE ?= default
FOLLOW ?= 1
TAIL ?= 100
# Freeze raw input before export: recursive Make variables would evaluate
# $(shell ...) and consume the dollar syntax intended for the container.
override PROFILE := $(value PROFILE)
override PROFILE_DIR := $(value PROFILE_DIR)
override CMD := $(value CMD)
override FOLLOW := $(value FOLLOW)
override TAIL := $(value TAIL)
export PROFILE PROFILE_DIR CMD FOLLOW TAIL
.PHONY: help init doctor build rebuild start stop restart recreate remove status logs proxy-restart firewall-logs shell exec pair smoke config

help:
	@echo 'make init       Set up local Python environment and YAML profile (PROFILE=default)'
	@echo 'make python-env Sync repo-local Python dependencies with uv'
	@echo 'make doctor     Check rootless Podman and host prerequisites'
	@echo 'make build      Build selected profile images (gateway when restricted)'
	@echo 'make start      Create/start the selected sandbox'
	@echo 'make stop       Stop it; keep the container and state'
	@echo 'make restart    Stop and start the existing container'
	@echo 'make rebuild    Pull bases and rebuild without cache using latest T3'
	@echo 'make recreate   Replace container using current image; retain home/project'
	@echo 'make remove     Remove container; retain home/project'
	@echo 'make shell      Open an interactive bash session'
	@echo 'make exec CMD="codex login --device-auth"'
	@echo 'make exec CMD="claude auth login"'
	@echo 'make exec CMD="gh auth status"'
	@echo 'make pair       Generate a fresh T3 pairing link'
	@echo 'make smoke      Check tools, network, and host file ownership'
	@echo 'make logs       Follow logs (Ctrl-C leaves container running)'
	@echo 'make proxy-restart  Apply allowlist edits without restarting T3'
	@echo 'make firewall-logs  Show policy denials (FOLLOW=0 TAIL=100 for finite output)'
	@echo 'make status     Show container status and published ports'
	@echo 'make config     Show resolved non-secret settings'

.PHONY: python-env
python-env:
	@command -v uv >/dev/null 2>&1 || { echo 'uv is required: https://docs.astral.sh/uv/getting-started/installation/' >&2; exit 1; }
	@uv sync --locked

init: python-env

init doctor build rebuild start stop restart recreate remove status logs proxy-restart firewall-logs shell exec pair smoke config:
	@bash scripts/sandbox.sh $@

# Unit discovery deliberately excludes the opt-in integration directory.
.PHONY: test test-integration
test:
	@PYTHONPATH=scripts uv run --locked python -m unittest discover -s tests -p 'test_*.py' -v

test-integration:
	@PYTHONPATH=scripts:tests/integration uv run --locked python -m unittest discover -s tests/integration -p 'test_*.py' -v
