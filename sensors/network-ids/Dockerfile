FROM python:3.13-slim-bookworm
WORKDIR /app
COPY sensors/network-ids/eve_adapter.py /app/eve_adapter.py
RUN chmod 0644 /app/eve_adapter.py
USER 10001:10001
ENTRYPOINT ["python3", "-I", "-B", "/app/eve_adapter.py"]
