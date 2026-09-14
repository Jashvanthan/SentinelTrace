FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# The default command will be overridden in docker-compose for celery
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
