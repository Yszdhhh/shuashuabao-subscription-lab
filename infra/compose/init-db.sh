#!/bin/bash
set -euo pipefail

# The official postgres image runs this script after the cluster is initialized.
# CREATE DATABASE is intentionally issued one database at a time because it
# cannot run inside a transaction.
if ! psql --username "$POSTGRES_USER" --dbname postgres --tuples-only --no-align \
    --command "SELECT 1 FROM pg_database WHERE datname = 'keygen'" | grep -q 1; then
  psql --username "$POSTGRES_USER" --dbname postgres --command "CREATE DATABASE keygen;"
fi

if ! psql --username "$POSTGRES_USER" --dbname postgres --tuples-only --no-align \
    --command "SELECT 1 FROM pg_database WHERE datname = 'keygate'" | grep -q 1; then
  psql --username "$POSTGRES_USER" --dbname postgres --command "CREATE DATABASE keygate;"
fi
