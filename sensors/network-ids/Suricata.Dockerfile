# Upstream engine remains a separately distributed GPLv2 process (OISF Suricata 8.0.7, the current
# stable release at the time of writing; the digest pins the exact image).
FROM jasonish/suricata:8.0.7@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26
USER root
# Upstream declares /etc/suricata (and the log/lib/run directories) as VOLUMEs: files changed there
# in a derived image do not persist, and the shipped files are 0600 for another UID. Copy the public
# default classification/reference/threshold files to a non-volume path, readable by any UID, and
# point the configuration at them explicitly. The runtime UID needs no access to /etc/suricata.
RUN mkdir -p /opt/clawforge/suricata /rules \
 && cp /etc/suricata/classification.config /etc/suricata/reference.config /etc/suricata/threshold.config /opt/clawforge/suricata/ \
 && chmod 0755 /opt/clawforge /opt/clawforge/suricata \
 && chmod 0644 /opt/clawforge/suricata/*.config
COPY sensors/network-ids/suricata.yaml /opt/clawforge/suricata/suricata.yaml
RUN chmod 0644 /opt/clawforge/suricata/suricata.yaml
# Root only until the capture socket is open: suricata.yaml `run-as` then drops to the image's
# unprivileged `suricata` user (998). Replay/validation runs override --user.
ENTRYPOINT ["/usr/bin/suricata"]
