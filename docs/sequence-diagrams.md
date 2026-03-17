# Zeek + ELK Sequence Diagrams

This page captures the main runtime and bootstrap flows in Mermaid sequence format.

## 1) End-to-End Analysis Flow

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant M as Makefile
    participant G as PCAP Generator
    participant Z as Zeek
    participant L as Logs Volume
    participant F as Filebeat
    participant E as Elasticsearch
    participant P as GeoIP Pipeline
    participant K as Kibana

    U->>M: make synth-run
    M->>G: make generate-pcap
    G-->>M: write data/sample.pcap
    M->>Z: make zeek-run
    Z->>L: write conn/dns/http/weird/notice/local_events logs
    F->>L: read *.log
    F->>E: index events (pipeline=zeek-geoip-pipeline)
    E->>P: enrich source.ip and destination.ip
    K->>E: query .ds-filebeat-* data stream
    U->>K: open Zeek Overview dashboard
```

## 2) Synthetic Traffic Generation and Processing

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant M as Makefile
    participant C as Docker Compose
    participant PG as pcap-generator service
    participant ZK as zeek service

    U->>M: make generate-pcap
    M->>C: docker compose run --rm pcap-generator
    C->>PG: execute generate_pcap.py
    PG-->>C: /data/sample.pcap ready

    U->>M: make zeek-run
    M->>C: docker compose exec zeek ... zeek -C -r /data/sample.pcap local
    C->>ZK: process sample.pcap with local.zeek
    ZK-->>U: logs written to logs/
```

## 3) ELK Bootstrap and Dashboard Provisioning

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant M as Makefile
    participant C as Docker Compose
    participant ES as Elasticsearch
    participant KB as Kibana
    participant FB as Filebeat
    participant S1 as bootstrap-elasticsearch.sh
    participant S2 as bootstrap-kibana.sh

    U->>M: make elk-up
    M->>C: start ES, KB, FB (profile elk)

    U->>M: make elastic-bootstrap
    M->>S1: run script
    S1->>ES: PUT zeek-geoip-pipeline

    U->>M: make kibana-bootstrap
    M->>S2: run script
    S2->>KB: create data view
    S2->>KB: create visualizations
    S2->>KB: create Zeek Overview dashboard
```

## 4) Custom Zeek Detection Path

```mermaid
sequenceDiagram
    autonumber
    participant T as Traffic
    participant Z as Zeek Engine
    participant LS as local.zeek Script
    participant NL as notice.log
    participant LL as local_events.log
    participant FB as Filebeat
    participant ES as Elasticsearch
    participant KB as Kibana

    T->>Z: Connection, DNS, HTTP activity
    Z->>LS: trigger events (connection_state_remove, dns_request, http_request)

    alt Threshold or suspicious behavior matched
        LS->>NL: write Notice::Type event
        LS->>LL: write structured local event
    else No match
        LS-->>Z: no custom alert
    end

    FB->>NL: parse notice records
    FB->>LL: parse zeek.local.* fields
    FB->>ES: ship enriched events
    KB->>ES: read metrics and tables for dashboard
```
