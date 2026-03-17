FROM docker.elastic.co/beats/filebeat:8.10.2

USER root

# Copy in our configuration and ensure it is owned by root (Filebeat requirement)
COPY filebeat.yml /usr/share/filebeat/filebeat.yml
RUN chown root:root /usr/share/filebeat/filebeat.yml \
    && chmod 0644 /usr/share/filebeat/filebeat.yml

# Switch back to the default non-root user for running the beat.
USER filebeat
