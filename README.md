# PLUS Middlebox using FD.io/VPP

## IETF hackathon code
Checkout branch *quic_IETF_hackathon*

## Installation
If not already available, install *Vagrant* and *VirtualBox* on your machine. 
Go to the Vagrant directory and execute:
```
vagrant up
vagrant ssh
```
To start Vagrant and connect via ssh (root access without password).

Part of the Vagrant setup adapted from the [vpp-mb](https://github.com/mami-project/vpp-mb) project.

## Additional Vagrant commands
Rsync the vpp-plus directory once more (e.g. useful after git pull):
```
cd vagrant
vagrant halt
rm .vagrant/machines/default/virtualbox/action_provision
vagrant up
vagrant ssh
```
Destroy the entire Vagrant VM and start over (important: you lose the entire VM and all custom files):
```
cd vagrant
vagrant halt
vagrant destroy
vagrant up
vagrant ssh
```

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

## Connect Vagrant VM to host machine and run go plus-echo test
This setup assumes you use VirtualBox as provider for the Vagrant VM!

On your local machine in VirtualBox: Go to `Virtualbox --> Preferences...`. In the "Network tab" add *two* "Host-only Networks". Change the configuration:
```
Network 1: IPv4 Address: 192.168.100.1, IPv4 Network Mask: 255.255.255.0
Network 2: IPv4 Address: 192.168.101.1, IPv4 Network Mask: 255.255.255.0
```
Now start the Vagrant VM and execute the following commands *inside the VM*:
```
sudo service vpp start
sudo vppctl ex /home/vagrant/plus-mb/scripts/external_vpp_interface.conf   # Add IPs to the interfaces inside VPP
sudo vppctl plus GigabitEthernet0/8/0                                      # Add interfaces to the plus plugin
sudo vppctl plus GigabitEthernet0/9/0
```
VPP should now be ready. Back on the *local machine*:
```
sudo route add 192.168.100.1/32 gw 192.168.101.2    # Add static routes for go client and server
sudo route add 192.168.101.1/32 gw 192.168.100.2
# if not available, install golan-1.9: sudo apt-get install golang-1.9-go
go get github.com/FMNSSun/plus-echo
cd go/src/github.com/FMNSSun/plus-echo
go build client.go
go build server.go
./server -local-addr=192.168.101.1:4000
./client -local-addr=192.168.100.1:3000 -remote-addr=192.168.101.1:4000    # in a different terminal
```
The go PLUS client should send a PLUS packet to the server and get a reply back.

In the Vagrant vm you should see two observed PlUS packets using e.g. `sudo vppctl plus stat`

**Important:** To add a packet trace, use `sudo vppctl trace add dpdk-input 50`.

## Simple example
Go to the *scripts* directory and make `ns_setup.sh` executable (`chmod +x ns_setup.sh`)

Execute `ns_setup.sh` to generate virtual namespaces veth pairs (`sudo ./ns_setup.sh`)

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
