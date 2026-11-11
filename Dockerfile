ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY cloud_resource_relay ./cloud_resource_relay
RUN python -m pip install --no-cache-dir . \
    && groupadd --gid 10001 relay \
    && useradd --uid 10001 --gid relay --no-create-home --shell /usr/sbin/nologin relay

USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["python", "-m", "cloud_resource_relay"]
CMD ["--config", "/app/config/config.yaml", "serve"]

