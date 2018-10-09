# VPP-based passive latency measurement middlebox

This VPP plugin adds support for passive latency measurements in FD.io.
The current implementation will estimate the RTT of:

- QUIC flows using the latency spin signal (and other techniques) described
    in our IMC'18 paper [Three Bits Suffice](https://nsg.ee.ethz.ch/fileadmin/user_upload/spinbit.pdf).
    The following [fork of minq](https://github.com/pietdevaere/minq) adds the latency spin signal to QUIC traffic
    such that it is detectable by the VPP plugin.
- TCP flows using the latency spin signal and/or TCP timestamps.
    We provide [patches](https://github.com/mami-project/three-bits-suffice/tree/master/tcp/kernel_patches)
    to add latency spin signal support to the Linux kernel.
- [PLUS](https://nsg.ee.ethz.ch/fileadmin/user_upload/CNSM_2017.pdf) flows using the PSN and PSE header fields.
   For example [puic-go](https://github.com/mami-project/puic-go) can be used to add PLUS support to quic-go.

## Installation 

You can either use Vagrant to set up everything automatically
or compile the plugin in an existing VPP installation.
The plugin is tested with the stable FD.io version 17.10. 

### Using Vagrant
If not already available, install *Vagrant* and *VirtualBox* on your machine. 
Go to the Vagrant directory and execute:
```
vagrant up
vagrant ssh
```
To start Vagrant and connect via ssh (root access without password).

Part of the Vagrant setup adapted from the [vpp-mb](https://github.com/mami-project/vpp-mb) project.

### Additional Vagrant commands
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

### Compiling the plugin
To compile the plugin manually or adapt changes inside Vagrant, use:
```
cd latency-plugin
sudo autoreconf -fis
sudo ./configure
sudo make
sudo make install
```

Restart VPP, e.g. `sudo service vpp restart`

## Important VPP commands
Start VPP: `sudo service vpp start`

Stop VPP: `sudo service vpp stop`

You can either access the VPP shell with `sudo vppctl` and then interactively execute commands (exit with `quit`) or execute each VPP command separately using: `sudo vppctl <cmd>`

Use `sudo vppctl help` for a list of supported commands.

### General commands
List of interfaces: `sudo vppctl show interface` (you can also shorten the commands, e.g. `sudo vppctl sh int`)

Show the VPP graph: `sudo vppctl show vlib graph`

Add a packet trace storing 50 packets `sudo vppctl trace add af-packet-input 50`

Display the captured packets in the trace: `sudo vppctl show trace`

Execute multiple VPP commands from a file (one command per line): `sudo vppctl exec <file>`

### Latency plugin specific commands
To get an overview, use: `sudo vppctl latency help`

Add an interface to the plugin: `sudo vppctl latency interface <interface>`

Remove an interface: `sudo vppctl latency interface <interface> disable`

List all currently active flows with latency estimations: `sudo vppctl latency stat`

Set the IPv4 address the plugin is listening to `sudo vppctl latency mb_ip <IPv4 (dot)>`

Add a UDP port number that indicates QUIC traffic `sudo vppctl latency quic_port <port>`
Can be repeated with different ports.

Add NAT-like functionalities `sudo vppctl latency nat <IPv4 (dot)> <port>`. This is useful if you
want to deploy the middlebox such that it can make on-path measurements taking traffic in
both direction into account. Can be repeated with different pairs of ports and IPs.
See next section for more information.

### On-path measurements
To be able to perform on-path measurements and observing traffic from the client
to the server **and** the reverse traffic, we added NAT-like functionalities to the
latency plugin.

As an example, assume the VPP middlebox has the IP 1.2.3.4 (defined with `sudo vppctl latency mb_ip 1.2.3.4`).
Now we would like to be able to forward traffic towards the server 5.6.7.8 through the middlebox.
For that, we arbitrarily associate port 8888 with the dst IP 5.6.7.8 and add that to the plugin with
(`sudo vppctl latency 5.6.7.8 8888`). Any client can now send traffic to 5.6.7.8 (over the middlebox)
by sending traffic towards the IP of the middlebox (1.2.3.4) with dst port 8888.
Whenever the plugin receives traffic with dst port 8888, it will:

1. save the observed src IP and replace it with its own IP (1.2.3.4)
1. replace the dst IP with the IP of the server 5.6.7.8
1. send the traffic towards the new destination (src and dst ports are not changed)

Once it receives traffic back from the server, it reverses the process and sends it to the original client.

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
