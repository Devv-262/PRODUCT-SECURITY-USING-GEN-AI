FROM python:3.8-slim

WORKDIR /app
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y openssl wget curl && \
    pip install --no-cache-dir -f requirements.txt

COPY app.py .
EXPOSE 5000

CMD ["python", "app.py"]
