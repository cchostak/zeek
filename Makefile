# Zeek learning scaffold commands

.PHONY: all build up down ps logs exec zeek-run elk-up elk-down elk-logs elk-reload-filebeat kibana-bootstrap

all: up

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

elk-up:
	docker compose --profile elk up -d

elk-down:
	docker compose --profile elk down

elk-logs:
	docker compose --profile elk logs -f

elk-reload-filebeat:
	docker compose --profile elk up -d --build filebeat

kibana-bootstrap:
	bash scripts/bootstrap-kibana.sh

ps:
	docker compose ps

logs:
	docker compose logs -f

exec:
	docker compose exec zeek /bin/bash

# process a sample pcap you put in ./data/sample.pcap
zeek-run:
	docker compose exec zeek /bin/sh -c "cd /logs && zeek -C -r /data/sample.pcap local"

# generate a sample pcap in data/sample.pcap
generate-pcap:
	docker compose run --rm pcap-generator

# generate and process in one command
synth-run: generate-pcap zeek-run
