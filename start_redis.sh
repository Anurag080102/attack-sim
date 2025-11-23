#!/usr/bin/env bash
redis-cli -p 6381 ping >/dev/null 2>&1 && { echo "Redis 6381 already running"; exit 0; }
redis-server --port 6381 --bind 127.0.0.1 --daemonize yes
redis-cli -p 6381 ping
