#!/usr/bin/env python3
"""Render the isolated ShuaBao download-edge nginx config.

Live production is uvicorn on :8010 and has no nginx today. This renderer
never emits listen 8010. TLS is assumed to terminate at an outer edge;
the generated server block is HTTP for the isolated download harness.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def render_downloads_config(*, releases_root: str, listen_port: int = 8088, server_name: str = "_") -> str:
    port = int(listen_port)
    if port == 8010 or port < 1 or port > 65535:
        raise SystemExit("refusing to render a download listener on port 8010 or an invalid port")
    root = str(releases_root).rstrip("/")
    if not root.startswith("/") or ".." in root or "\n" in root or " " in root:
        raise SystemExit("releases_root must be an absolute path without spaces or ..")
    name = server_name.strip() or "_"
    if any(ch.isspace() for ch in name) or ";" in name:
        raise SystemExit("server_name is not safe")
    return f"""# ShuaBao immutable artifact download edge.
# Isolated from the subscription bridge. Do not listen on 8010.
# Live host currently has no nginx and no docker; this file is not deployed.
# TLS termination is assumed at the outer edge (cloudflared or a TLS proxy).
# This server block itself is HTTP so an isolated test can exercise static serving.
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/shuabao-downloads-nginx.pid;
events {{ worker_connections 128; }}
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    tcp_nopush on;
    server_tokens off;
    autoindex off;
    # range requests stay at nginx default (do not set max_ranges 0)
    types {{
        application/zip zip;
        application/json json;
        application/octet-stream sig;
    }}

    server {{
        listen {port};
        server_name {name};
        autoindex off;

        # staging, withdrawn, index, and audit are never public aliases
        location ^~ /downloads/shuabao/staging/ {{ deny all; }}
        location ^~ /downloads/shuabao/withdrawn/ {{ deny all; }}
        location ^~ /downloads/shuabao/index/ {{ deny all; }}
        location ^~ /downloads/shuabao/audit/ {{ deny all; }}
        location ^~ /downloads/shuabao/staging {{ deny all; }}
        location ^~ /downloads/shuabao/withdrawn {{ deny all; }}

        # reject dotted and traversal-looking path segments before alias
        location ~ /\\. {{ deny all; }}
        location ~ \\.\\. {{ deny all; }}

        # only immutable published channel artifacts
        location ~ ^/downloads/shuabao/(dev|internal-pilot|external-beta|release)/([0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?)/(shuabao[A-Za-z0-9._-]*\\.zip|release-descriptor\\.json|release-descriptor\\.sig)$ {{
            alias {root}/$1/$2/$3;
            autoindex off;
            disable_symlinks on;
            add_header Cache-Control "public, max-age=31536000, immutable" always;
            add_header X-Content-Type-Options "nosniff" always;
        }}

        location / {{
            return 404;
        }}
    }}
}}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Render ShuaBao download nginx config")
    parser.add_argument("--releases-root", required=True)
    parser.add_argument("--listen-port", type=int, default=8088)
    parser.add_argument("--server-name", default="_")
    parser.add_argument("--output", default="-")
    args = parser.parse_args()
    text = render_downloads_config(
        releases_root=args.releases_root,
        listen_port=args.listen_port,
        server_name=args.server_name,
    )
    if args.output == "-":
        print(text, end="")
    else:
        Path(args.output).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
