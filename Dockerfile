FROM anchore/grype@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c AS grype
FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ARG AUDIT_UID=1111
ARG AUDIT_GID=1111
RUN groupadd --gid "${AUDIT_GID}" audit \
    && useradd --uid "${AUDIT_UID}" --gid "${AUDIT_GID}" \
       --no-create-home --home-dir /tmp --shell /usr/sbin/nologin audit
COPY --from=grype /grype /usr/local/bin/grype
COPY audit.py dashboard.html /opt/swarm-software-audit/
COPY host/ /opt/swarm-software-audit/host/
COPY LICENSE /usr/share/doc/swarm-software-audit/LICENSE
ARG VERSION=development
LABEL org.opencontainers.image.source="https://github.com/pacificclimate/swarm-software-audit" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.version="${VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Run with the image account UID:GID matching the output mount owner.
ENTRYPOINT ["python", "/opt/swarm-software-audit/audit.py"]
CMD ["--help"]
