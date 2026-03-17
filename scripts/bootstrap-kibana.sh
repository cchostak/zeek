#!/usr/bin/env bash
set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://localhost:5602}"
DATA_VIEW_ID="zeek-filebeat-data-view"
INDEX_PATTERN_TITLE=".ds-filebeat-*"

wait_for_kibana() {
  echo "Waiting for Kibana at ${KIBANA_URL} ..."
  for _ in $(seq 1 90); do
    if curl -sS "${KIBANA_URL}/api/status" >/dev/null 2>&1; then
      echo "Kibana is reachable."
      return 0
    fi
    sleep 2
  done

  echo "Kibana did not become reachable in time." >&2
  return 1
}

kibana_post() {
  local path="$1"
  local payload="$2"

  curl -sS -X POST "${KIBANA_URL}${path}" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "${payload}" >/dev/null
}

wait_for_kibana

echo "Creating Zeek data view..."
kibana_post "/api/saved_objects/index-pattern/${DATA_VIEW_ID}?overwrite=true" '{"attributes":{"title":".ds-filebeat-*","name":"Zeek Filebeat","timeFieldName":"@timestamp"}}'

kibana_post "/api/data_views/default" '{"data_view_id":"zeek-filebeat-data-view","force":true}'

echo "Creating saved searches..."
kibana_post "/api/saved_objects/search/zeek-conn-search?overwrite=true" '{"attributes":{"title":"Zeek Connections","columns":["zeek.conn.uid","zeek.conn.orig_h","zeek.conn.resp_h","zeek.conn.proto","zeek.conn.service","zeek.conn.duration","zeek.conn.conn_state"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"zeek.log_type: conn\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"zeek-filebeat-data-view"}]}'

kibana_post "/api/saved_objects/search/zeek-dns-search?overwrite=true" '{"attributes":{"title":"Zeek DNS","columns":["zeek.dns.uid","zeek.dns.query","zeek.dns.qtype_name","zeek.dns.rcode_name","zeek.dns.answers"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"zeek.log_type: dns\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"zeek-filebeat-data-view"}]}'

kibana_post "/api/saved_objects/search/zeek-http-search?overwrite=true" '{"attributes":{"title":"Zeek HTTP","columns":["zeek.http.uid","zeek.http.method","zeek.http.host","zeek.http.uri","zeek.http.status_code"],"sort":[["@timestamp","desc"]],"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"zeek.log_type: http\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}},"references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"zeek-filebeat-data-view"}]}'

echo "Creating dashboard..."
kibana_post "/api/saved_objects/dashboard/zeek-overview-dashboard?overwrite=true" '{"attributes":{"title":"Zeek Overview","description":"Starter dashboard with parsed Zeek conn/dns/http streams","hits":0,"optionsJSON":"{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}","panelsJSON":"[{\"version\":\"8.10.2\",\"type\":\"search\",\"panelIndex\":\"1\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":10,\"i\":\"1\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"version\":\"8.10.2\",\"type\":\"search\",\"panelIndex\":\"2\",\"gridData\":{\"x\":0,\"y\":10,\"w\":24,\"h\":10,\"i\":\"2\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"},{\"version\":\"8.10.2\",\"type\":\"search\",\"panelIndex\":\"3\",\"gridData\":{\"x\":24,\"y\":10,\"w\":24,\"h\":10,\"i\":\"3\"},\"embeddableConfig\":{},\"panelRefName\":\"panel_3\"}]","timeRestore":false,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"language\":\"kuery\",\"query\":\"\"},\"filter\":[]}"}},"references":[{"name":"panel_1","type":"search","id":"zeek-conn-search"},{"name":"panel_2","type":"search","id":"zeek-dns-search"},{"name":"panel_3","type":"search","id":"zeek-http-search"}]}'

echo "Dashboard created. Open: ${KIBANA_URL}/app/dashboards#/view/zeek-overview-dashboard"
