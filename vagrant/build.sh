#!/bin/bash

# Install VPP v17.10 (Ubuntu 16.04 Xenial)
echo "deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.stable.1710.ubuntu.xenial.main/ ./" | tee -a /etc/apt/sources.list.d/99fd.io.list
apt-get update
apt-get install -y git vpp vpp-lib vpp-dev vpp-dbg vpp-dpdk-dev vpp-dpdk-dkms vpp-plugins vpp-api-java vpp-api-lua vpp-api-python autoconf libtool traceroute python-scapy

# Compile/Install latency plugin
service vpp stop
(cd /home/vagrant/vpp-latency-mb/latency-plugin; autoreconf -fis; ./configure; make; make install)

