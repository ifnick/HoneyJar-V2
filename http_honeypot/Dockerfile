FROM python:3.11-slim
WORKDIR /app
RUN apt-get update -qq && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY honeypot.py .
CMD ["python", "-u", "honeypot.py"]
