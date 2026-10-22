.DEFAULT_GOAL := help
.PHONY: help init doctor build rebuild start stop restart recreate remove status logs shell exec pair smoke config

help:
	@echo 'make init       Create .env from .env.example'
	@echo 'make doctor     Check rootless Podman and host prerequisites'
	@echo 'make build      Build the image for the current WSL user'
	@echo 'make start      Create/start the selected sandbox'
	@echo 'make stop       Stop it; keep the container and state'
	@echo 'make restart    Stop and start the existing container'
	@echo 'make rebuild    Pull bases and rebuild without cache'
	@echo 'make recreate   Replace container using current image; retain home/project'
	@echo 'make remove     Remove container; retain home/project'
	@echo 'make shell      Open an interactive bash session'
	@echo 'make exec CMD="codex login --device-auth"'
	@echo 'make pair       Generate a fresh T3 pairing link'
	@echo 'make smoke      Check tools, network, and host file ownership'
	@echo 'make logs       Follow logs (Ctrl-C leaves container running)'
	@echo 'make status     Show container status and published ports'
	@echo 'make config     Show resolved non-secret settings'

init doctor build rebuild start stop restart recreate remove status logs shell exec pair smoke config:
	@bash scripts/sandbox.sh $@
