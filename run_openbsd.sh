#!/bin/sh

export DHCPD_LEASES_FILE=/var/db/dhcpd.leases
export OUI_FILE=/home/aaron/oui.txt

target/release/rust-dhcp-leases
