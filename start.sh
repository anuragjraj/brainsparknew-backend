#!/usr/bin/env bash
set -e
gunicorn math_service:app -b 127.0.0.1:7001 --workers 1 --timeout 30 &
exec node server.js