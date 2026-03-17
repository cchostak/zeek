# Zeek Learning Scaffold

This repo is built for experimentation with Zeek via Docker Compose.

## Structure

- `docker-compose.yml`: single Zeek service.
- `zeek/Dockerfile`: image based on `zeek/zeek:5.0`.
- `zeek-scripts/`: Zeek scripts mapped into container site package.
- `data/`: drop PCAP files to inspect.
- `logs/`: output for extracted Zeek logs.
- `Makefile`: quick commands to manage stack.

## Quick Start

1. Build and start (background):

   ```bash
   make build
   make up
   ```

2. Open a shell inside container:

   ```bash
   make exec
   zeek -v
   ```

3. Import a pcap for processing:

   ```bash
   cp /path/to/foo.pcap data/sample.pcap
   make zeek-run
   ls logs
   ```

4. Add scripts in `zeek-scripts/` and run Zeek with them:

   ```bash
   make exec
   zeek -C -r /data/sample.pcap local
   ```

5. Stop:

   ```bash
   make down
   ```

## Traffic generation workflow

1. Generate synthetic PCAP with Zeek-compatible flows:

   ```bash
   make generate-pcap
   ls data/sample.pcap
   ```

2. Run Zeek analysis and dump logs:

   ```bash
   make zeek-run
   ls logs
   cat logs/conn.log
   ```

3. One-step demo:

   ```bash
   make synth-run
   ```

## Notes

- `zeek` service is configured to remain running with a sleep loop for interactive use.
- For packet capture live interfaces, best run Zeek on dedicated network namespace and avoid host traffic contamination.

## ELK + Parsed Zeek Logs

1. Start Elasticsearch, Kibana, and Filebeat:

   ```bash
   make elk-up
   ```

2. Rebuild Filebeat if parsing config changes:

   ```bash
   make elk-reload-filebeat
   ```

3. Generate traffic and Zeek logs:

   ```bash
   make synth-run
   ```

4. Create Kibana data view + starter dashboard:

   ```bash
   make kibana-bootstrap
   ```

5. Open Kibana:

   - URL: `http://localhost:5602`
   - Dashboard: `Zeek Overview`

### Parsed fields included

- `zeek.log_type` (derived from log filename)
- `zeek.conn.*` for `conn.log`
- `zeek.dns.*` for `dns.log`
- `zeek.http.*` for `http.log` (core fields + remaining tail)
- `zeek.weird.*` for `weird.log`

Comment/header rows from Zeek logs (lines starting with `#`) are dropped at ingest time.
