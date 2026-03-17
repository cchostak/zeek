#!/usr/bin/env bash
set -euo pipefail

ELASTIC_URL="${ELASTIC_URL:-http://localhost:9201}"
PIPELINE_ID="zeek-geoip-pipeline"

wait_for_elasticsearch() {
  echo "Waiting for Elasticsearch at ${ELASTIC_URL} ..."
  for _ in $(seq 1 90); do
    if curl -sS "${ELASTIC_URL}" >/dev/null 2>&1; then
      echo "Elasticsearch is reachable."
      return 0
    fi
    sleep 2
  done

  echo "Elasticsearch did not become reachable in time." >&2
  return 1
}

wait_for_elasticsearch

echo "Creating ingest pipeline: ${PIPELINE_ID}"
curl -sS -X PUT "${ELASTIC_URL}/_ingest/pipeline/${PIPELINE_ID}" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "GeoIP enrichment for Zeek source/destination IP addresses",
    "processors": [
      {
        "geoip": {
          "field": "source.ip",
          "target_field": "source.geo",
          "ignore_missing": true
        }
      },
      {
        "geoip": {
          "field": "destination.ip",
          "target_field": "destination.geo",
          "ignore_missing": true
        }
      }
    ]
  }' >/dev/null

echo "Ingest pipeline ready: ${PIPELINE_ID}"
