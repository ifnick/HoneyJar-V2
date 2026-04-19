FROM alpine:3.19
RUN apk add --no-cache python3 docker-cli iptables
COPY watcher.py /app/watcher.py
CMD ["python3", "/app/watcher.py"]
