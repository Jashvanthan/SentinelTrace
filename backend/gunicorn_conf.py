"""
SentinelTrace — Production Gunicorn Configuration for Uvicorn Workers
Provides multi-process ASGI concurrency, memory leak prevention, and load resilience.
"""
import multiprocessing
import os

# Worker concurrency: Auto-calculate from CPU cores or override via env
default_workers = max(2, min(8, multiprocessing.cpu_count() * 2))
workers = int(os.environ.get("WEB_CONCURRENCY", default_workers))
worker_class = "uvicorn.workers.UvicornWorker"

# Socket binding
bind = f"{os.environ.get('HOST', '0.0.0.0')}:{os.environ.get('PORT', '8000')}"
backlog = 2048

# Worker Lifecycle & Crash Prevention
# Recycle workers after processing N requests to prevent memory bloat/leaks
max_requests = int(os.environ.get("MAX_REQUESTS", 5000))
max_requests_jitter = int(os.environ.get("MAX_REQUESTS_JITTER", 500))

# Timeouts: Allow long-running threat intelligence & ML parsing without timing out prematurely
timeout = int(os.environ.get("WORKER_TIMEOUT", 120))
graceful_timeout = int(os.environ.get("GRACEFUL_TIMEOUT", 30))
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()

def post_fork(server, worker):
    server.log.info(f"Worker spawned (pid: {worker.pid}) with {workers} total workers configured.")

def worker_exit(server, worker):
    server.log.info(f"Worker exiting gracefully (pid: {worker.pid})")
