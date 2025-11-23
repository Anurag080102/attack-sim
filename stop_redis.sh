#!/usr/bin/env bash
redis-cli -p 6381 shutdown || echo "Redis 6381 not running"
