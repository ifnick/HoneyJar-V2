FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask flask-sqlalchemy psycopg2-binary werkzeug
COPY app.py .
COPY templates ./templates
COPY static ./static
CMD ["python", "-u", "app.py"]
