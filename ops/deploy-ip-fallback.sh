#!/usr/bin/env bash
set -euo pipefail

readonly BACKUP_SUFFIX=.bak-20261024d-codex
readonly CONFIG=/etc/shuabao/ip-fallback-nginx.conf
readonly SERVICE=/etc/systemd/system/shuabao-ip-fallback.service
readonly CERT_DIR=/etc/shuabao/ip-fallback
readonly CERT=${CERT_DIR}/server.crt
readonly KEY=${CERT_DIR}/server.key
readonly STATE_DIR=/var/lib/shuabao-ip-fallback

backup_path() {
    local path=$1
    if [[ -e "${path}" && ! -e "${path}${BACKUP_SUFFIX}" ]]; then
        cp -a -- "${path}" "${path}${BACKUP_SUFFIX}"
    fi
}

install -d -m 0755 /etc/shuabao "${CERT_DIR}" "${STATE_DIR}"
chown root:root "${STATE_DIR}"
touch "${STATE_DIR}/access.log" "${STATE_DIR}/error.log"
chown root:root "${STATE_DIR}/access.log" "${STATE_DIR}/error.log"
chmod 0640 "${STATE_DIR}/access.log" "${STATE_DIR}/error.log"
chmod 0755 "${CERT_DIR}"

backup_path "${CONFIG}"
backup_path "${SERVICE}"
backup_path "${CERT}"
backup_path "${KEY}"

install -m 0644 /dev/stdin "${CONFIG}" <<'NGINX'
user www-data;
worker_processes 1;
pid /run/shuabao-ip-fallback/nginx.pid;
error_log /var/lib/shuabao-ip-fallback/error.log warn;

events {
    worker_connections 512;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server_tokens off;

    map $http_user_agent $shb_client_ua {
        default 0;
        "~^ShuaBaoClient/" 1;
    }

    limit_req_zone $binary_remote_addr zone=shb_ip:10m rate=10r/s;
    access_log /var/lib/shuabao-ip-fallback/access.log combined;

    server {
        listen 0.0.0.0:8443 ssl;
        server_name 134.175.153.157;
        ssl_certificate /etc/shuabao/ip-fallback/server.crt;
        ssl_certificate_key /etc/shuabao/ip-fallback/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:shb_ip_fallback_ssl:1m;

        if ($shb_client_ua = 0) {
            return 403;
        }

        location / {
            limit_req zone=shb_ip burst=30 nodelay;
            limit_req_status 429;
            proxy_pass http://127.0.0.1:18011;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header CF-Connecting-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP "";
            proxy_set_header True-Client-IP "";
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Connection "";
        }
    }
}
NGINX

install -m 0644 /dev/stdin "${SERVICE}" <<'UNIT'
[Unit]
Description=ShuaBao IP fallback HTTPS entrypoint
After=network-online.target shuabao-origin-filter.service
Wants=network-online.target
Requires=shuabao-origin-filter.service

[Service]
Type=simple
RuntimeDirectory=shuabao-ip-fallback
RuntimeDirectoryMode=0755
ExecStartPre=/usr/sbin/nginx -t -c /etc/shuabao/ip-fallback-nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/shuabao/ip-fallback-nginx.conf -g 'daemon off; master_process on;'
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT

if [[ ! -e "${KEY}" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "${KEY}"
    chmod 0600 "${KEY}"
fi

if [[ ! -e "${CERT}" ]]; then
    openssl req -x509 -new -sha256 -days 3650 -key "${KEY}" -out "${CERT}" \
        -subj '/CN=134.175.153.157' \
        -addext 'subjectAltName=IP:134.175.153.157' \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
        -addext 'extendedKeyUsage=serverAuth'
    chmod 0644 "${CERT}"
fi

test "$(stat -c '%a' "${KEY}")" = 600
chown root:root "${KEY}" "${CERT}"
chmod 0600 "${KEY}"
chmod 0644 "${CERT}"

systemctl daemon-reload
systemctl enable --now shuabao-ip-fallback.service
nginx -t -c "${CONFIG}"
systemctl --no-pager --full status shuabao-ip-fallback.service
ufw allow 8443/tcp comment 'ShuaBao IP fallback HTTPS'
ufw status numbered
