#!/bin/sh
# Blackbox installer: sudo ./install.sh (asks each setting; see ./blackbox install -h for options)
set -e
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then
	exec sudo "$0" "$@"
fi
./blackbox install "$@"
