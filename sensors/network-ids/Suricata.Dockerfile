# Upstream engine remains a separately distributed GPLv2 process.
FROM jasonish/suricata:8.0.7@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26
USER root
# Upstream config files are 0600 under a different UID. Permit the configurable
# non-root runtime user to read public classifications/references/thresholds.
RUN chmod a+r /etc/suricata/*.config
USER 10001:10001
ENTRYPOINT ["/usr/bin/suricata"]
