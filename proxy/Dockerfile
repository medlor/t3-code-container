FROM docker.io/library/debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONPATH=/opt/t3-proxy
RUN apt-get update && apt-get install -y --no-install-recommends \
    squid nftables socat python3 python3-yaml ca-certificates util-linux libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 2001 t3-proxy && useradd --uid 2001 --gid 2001 --no-create-home t3-proxy \
    && groupadd --gid 2002 t3-relay && useradd --uid 2002 --gid 2002 --no-create-home t3-relay \
    && groupadd --gid 2003 t3-supervisor && useradd --uid 2003 --gid 2003 --no-create-home t3-supervisor \
    && rm -f /etc/squid/squid.conf
COPY scripts/t3_sandbox/__init__.py scripts/t3_sandbox/policy.py scripts/t3_sandbox/denials.py /opt/t3-proxy/t3_sandbox/
COPY proxy/runtime.py /opt/t3-proxy/runtime.py
ENTRYPOINT ["python3", "/opt/t3-proxy/runtime.py"]
CMD ["serve", "--snapshot", "/run/t3-policy/active.json"]
