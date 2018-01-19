# PLUS Middlebox using FD.io/VPP
## Installation
If not already available, install *Vagrant* and *VirtualBox* on your machine. 
Go to the Vagrant directory and execute:
```
vagrant up
vagrant ssh
```
To start Vagrant and connect via ssh (root access without password).

Part of the Vagrant setup adapted from the [vpp-mb](https://github.com/mami-project/vpp-mb) project.

## Important VPP commands
Start VPP: `sudo service vpp start`

Stop VPP: `sudo service vpp stop`

You can either access the VPP shell with `sudo vppctl` and then interactively execute commands (exit with `quit`) or execute each VPP command separately using: `sudo vppctl <cmd>`

Use `sudo vppctl help` for a list of supported commands.

### Important general commands
List of interfaces: `sudo vppctl show interface` (you can also shorten the commands, e.g. `sudo vppctl sh int`)

Show the VPP graph: `sudo vppctl show vlib graph`

Add packet trace for (50 packets) `sudo vppctl trace add af-packet-input 50`

Display the trace: `sudo vppctl show trace`

Execute multiple commands from a file: `sudo vppctl exec <file>`

### PLUS specific commands
Add an interface to the PLUS plugin: `sudo vppctl plus <interface>`

Remove an interface: `sudo vppctl plus <interface> disable`

List all active PLUS flows: `sudo vppctl plus stat`

## Simple example
Go to the *scripts* directory and make `ns_setup.sh` executable (`chmod +x ns_setup.sh`)

Execute `ns_setup.sh` to generate virtual namespace veth pairs (`sudo ./ns_setup.sh`)

Start VPP: `sudo service vpp start`

Execute the file `vpp_interface.conf` to connect the virtual namespaces to VPP:

`sudo vppctl exec /home/vagrant/plus-mb/scripts/vpp_interface.conf`

(Use `sudo vppctl sh int` to confirm that the new interfaces are visible: *host-vpp1* and *host-vpp2*)

Add the two interfaces to the PLUS plugin, such that it analyzes traffic coming from these interfaces:

`sudo vppctl plus host-vpp1` and `sudo vppctl plus host-vpp2`

Use the (very basic) Python scripts to generate PLUS traffic. The sender and receiver are each executed in a separate namespace (connected via VPP).

Receiver: `sudo ip netns exec vpp2 python receiver.py`

Sender: `sudo ip netns exec vpp1 python sender.py`

Use `sudo vppctl plus stat` to see the generated flow or use the packet trace commands from above.

## Ongoing work
* Performance improvements (implementation of double loop)
* Full multi-thread support
* More test cases
* Support for moving endpoints (e.g. src IP change)
* Support for IP headers with options
* IPv6 support

## Known limitations
* Currently only support for 2048 concurrent flows (should be more than enough for initial tests)

# QUIC VPP plugin
## Installation
See above. The new files are in the directory quic-plugin. There is also a pcap test file in the pcap directory.

## Compile the plugin
During the Vagrant provision, the plugins are automatically compiled and added to VPP.

To compile new changes:

```
cd quic-plugin
sudo autoreconf -fis
sudo ./configure
sudo make
sudo make install
```

Restart VPP.

## QUIC specific commands
Add an interface to the QUIC plugin: `sudo vppctl quic <interface>`

Remove an interface: `sudo vppctl quic <interface> disable`

List all active QUIC flows: `sudo vppctl quic stat`

## Simple example
Go to the *scripts* directory and make `ns_setup.sh` executable (`chmod +x ns_setup.sh`)

Execute `ns_setup.sh` to generate virtual namespace veth pairs (`sudo ./ns_setup.sh`)

Start VPP: `sudo service vpp start`

Execute the file `vpp_interface.conf` to connect the virtual namespaces to VPP:

`sudo vppctl exec /home/vagrant/plus-mb/scripts/vpp_interface.conf`

Add one interface to the QUIC plugin, such that it analyzes traffic coming from this interface:

`sudo vppctl quic host-vpp1`

(Track all 250 packets: `sudo vppctl trace add af-packet-input 250`)

Replay a pcap file with 250 QUIC packets:

`sudo ip netns exec vpp1 tcpreplay --intf1=veth_vpp1 /home/vagrant/plus-mb/pcap/delay-10-ms-first-250-pkt.pcap`

(Save the collected trace in a file: `sudo vppctl sh trace max 250 > /home/vagrant/trace.txt`)

(Look at the current QUIC stats: `sudo vppctl quic stat`)

Stop VPP: `sudo service vpp stop`

The QUIC plugin writes RTT estimations to the stdout. To view them, look at the corresponding log:

`sudo journalctl -u vpp`
