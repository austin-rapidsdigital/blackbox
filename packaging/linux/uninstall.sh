#!/bin/sh
# Removes the Blackbox timer. Reports and collected data are kept.
set -e
if [ "$(id -u)" -ne 0 ]; then
	exec sudo "$0" "$@"
fi
/usr/local/bin/blackbox uninstall
