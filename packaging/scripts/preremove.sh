#!/bin/sh
if command -v systemctl >/dev/null 2>&1; then systemctl stop licd.service >/dev/null 2>&1 || true; fi
