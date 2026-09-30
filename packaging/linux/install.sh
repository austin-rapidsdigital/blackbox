#!/bin/sh
# Blackbox installer: ./install.sh [--site NAME] [--report-every daily|weekly|monthly]
set -e
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then
	exec sudo "$0" "$@"
fi
./blackbox install "$@"
