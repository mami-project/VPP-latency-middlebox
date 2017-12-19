# PLUS Middlebox using FD.io/VPP
## Installation
If not already available, install *Vagrant* and *VirtualBox* on your machine. 
Go to the Vagrant directory and execute:
```
vagrant up
vagrant ssh
```
To start Vagrant and connect via ssh (root access without password).

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
Execute `ns_setup.sh` to generate virtual namespaces veth pairs (`sudo ./ns_setup.sh`)
Start VPP: `sudo service vpp start`
Execute the file `vpp_interface.conf` to connect the virtual namespaces to VPP: `sudo vppctl exec /home/vagrant/plus-mb/scripts/vpp_interface.conf`
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

## Known problems (fixed very soon)
* PSN/PSE overflow is not fully supported
* Currently only support for 2048 concurrent flows (should be more than enough for initial tests)
* Sometimes the RTT estimation is not correct