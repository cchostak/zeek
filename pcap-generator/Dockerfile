FROM python:3.12-slim
LABEL maintainer="learn-zeek@example.com"

RUN pip install --no-cache-dir scapy

WORKDIR /app
COPY generate_pcap.py /app/generate_pcap.py
RUN chmod +x /app/generate_pcap.py

VOLUME ["/data"]

CMD ["python", "/app/generate_pcap.py"]
