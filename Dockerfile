FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /service
COPY requirements-lock.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-lock.txt \
    && groupadd --gid 10001 centaurus \
    && useradd --uid 10001 --gid centaurus --no-create-home centaurus
COPY app ./app
COPY app_v4 ./app_v4
COPY scripts/abyssal.py ./scripts/abyssal.py
USER 10001:10001
EXPOSE 8443
CMD ["python", "-m", "uvicorn", "app_v4.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8443", "--no-proxy-headers", "--no-server-header", "--limit-concurrency", "64", "--timeout-keep-alive", "5", "--h11-max-incomplete-event-size", "8192", "--ssl-keyfile", "/run/tls/key.pem", "--ssl-certfile", "/run/tls/cert.pem"]
