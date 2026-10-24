#!/usr/bin/env bash
set -euo pipefail

readonly BACKUP_SUFFIX=.bak-20261024d-codex
readonly CONFIG=/etc/shuabao/ip-fallback-nginx.conf
readonly SERVICE=/etc/systemd/system/shuabao-ip-fallback.service
readonly CERT_DIR=/etc/shuabao/ip-fallback
readonly CERT=${CERT_DIR}/server.crt
readonly KEY=${CERT_DIR}/server.key

systemctl disable --now shuabao-ip-fallback.service 2>/dev/null || true
ufw delete allow 8443/tcp 2>/dev/null || true

restore_path() {
    local path=$1
    if [[ -e "${path}${BACKUP_SUFFIX}" ]]; then
        rm -f -- "${path}"
        mv -- "${path}${BACKUP_SUFFIX}" "${path}"
    else
        rm -f -- "${path}"
    fi
}

restore_path "${CONFIG}"
restore_path "${SERVICE}"
restore_path "${CERT}"
restore_path "${KEY}"
rmdir "${CERT_DIR}" 2>/dev/null || true
systemctl daemon-reload
