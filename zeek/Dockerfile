FROM zeek/zeek:5.0
LABEL maintainer="learn-zeek@example.com"

WORKDIR /root

# Ensure directories are present
RUN mkdir -p /data /logs /usr/local/zeek/share/zeek/site

# Add helpers and sample scripts (mounted on docker-compose override while deving)
COPY zeek-scripts /usr/local/zeek/share/zeek/site

RUN chmod -R 777 /data /logs /usr/local/zeek/share/zeek/site

# Keep container up for interactive experimentation
ENTRYPOINT ["tail", "-f", "/dev/null"]
