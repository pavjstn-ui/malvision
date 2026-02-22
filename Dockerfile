FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy engine source
COPY engine/ ./engine/

# Logs and queue file land in /app/data (mount as volume)
RUN mkdir -p /app/data

WORKDIR /app/engine

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
