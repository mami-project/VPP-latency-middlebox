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

Add a packet trace storing 50 packets `sudo vppctl trace add dpdk-input 50`

Display the captured packets in the trace: `sudo vppctl show trace`

Execute multiple VPP commands from a file (one command per line): `sudo vppctl exec <file>`

### Latency plugin specific commands
To get an overview, use: `sudo vppctl latency help`

Add an interface to the plugin: `sudo vppctl latency interface <interface>`

Remove an interface: `sudo vppctl latency interface <interface> disable`

List all currently active flows with latency estimations: `sudo vppctl latency stats`

Set the IPv4 address the plugin is listening to `sudo vppctl latency mb_ip <IPv4 (dot)>`

Add a UDP port number that indicates QUIC traffic `sudo vppctl latency quic_port <port>`.
Can be repeated with different ports.

Add NAT-like functionalities `sudo vppctl latency nat <IPv4 (dot)> <port>`. This is useful if you
want to deploy the middlebox such that it can make on-path measurements taking traffic in
both directions into account. Can be repeated with different pairs of ports and IPs.
See next section for more information.

## On-path latency measurements
To be able to perform on-path measurements and observing traffic from the client
to the server **and** the reverse traffic, we added NAT-like functionalities to the
latency plugin.

As an example, assume the VPP middlebox has the IP 1.2.3.4 (defined with `sudo vppctl latency mb_ip 1.2.3.4`).
Now we would like to be able to forward traffic towards the server 5.6.7.8 through the middlebox.
For that, we arbitrarily associate port 8888 with the dst IP 5.6.7.8 and add that to the plugin with
`sudo vppctl latency 5.6.7.8 8888`. Any client can now send traffic to 5.6.7.8 (over the middlebox)
by sending traffic towards the IP of the middlebox (1.2.3.4) with dst port 8888.
Whenever the plugin receives traffic with dst port 8888, it will:

1. save the observed src IP and replace it with its own IP (1.2.3.4)
1. replace the dst IP with the IP of the corresponding server (5.6.7.8)
1. send the traffic towards the new destination (src and dst ports are not changed)

Once it receives traffic back from the server, it reverses the process and sends it to the original client.

Following a list of sample commands to configure VPP and the plugin to implement the previous example.
We assume that the server running VPP is inside a network with IP space 1.2.3.0/24 and the gateway
towards the Internet has the IP 1.2.3.1. The VPP server has one interface (called `GigabitEthernet3/0/0`).
The actual interface name depends one the used implementation/hardware and can be found with `sudo vppctl sh int`.

```
 set int state GigabitEthernet3/0/0 up
 set int ip address GigabitEthernet3/0/0 1.2.3.4/24
 ip route add 0.0.0.0/0 via 1.2.3.1 GigabitEthernet3/0/0
 latency interface GigabitEthernet3/0/0
 latency mb_ip 1.2.3.4
 latency nat 5.6.7.8 8888
 latency quic_port 8888
```

The last command declares traffic towards/from port 8888 as QUIC traffic.
All these commands can be saved in a file (e.g. `setup.conf`) and executed
with `sudo vppctl exec setup.conf`.

### Connect Vagrant to host machine

If you use the Vagrant installation and want to connect the VM to the host machine,
use "Host-only Networks" (assuming VirtualBox as provider for the Vagrant VM).
On your local machine in VirtualBox: Go to `Virtualbox --> Preferences...`.
In the "Network tab" add two "Host-only Networks" and change the configuration:
```
Network 1: IPv4 Address: 192.168.100.1, IPv4 Network Mask: 255.255.255.0
Network 2: IPv4 Address: 192.168.101.1, IPv4 Network Mask: 255.255.255.0
```

Restart the Vagrant VM and VPP should see the interfaces when using `sudo vppctl sh int`
as `GigabitEthernet0/8/0` and `GigabitEthernet0/9/0`. Add the corresponding IPs:
```
set int state GigabitEthernet0/8/0 up
set int ip address GigabitEthernet0/8/0 192.168.100.2/24
set int state GigabitEthernet0/9/0 up
set int ip address GigabitEthernet0/9/0 192.168.101.2/24
```

## Measurement results

The VPP plugin writes latency measurement results to the `/tmp` folder using different
files for QUIC, TCP and PLUS traffic (`/tmp/latency_{plus,tcp,quic}_printf.out`).
The data is saved as CSV files. All latency estimations are in seconds.

### QUIC latency measurements
Header of the CSV file: `time,pn,host,spin_data,spin_new,pn_spin_data,pn_spin_new,vec_data,vec_new,heur_data,heur_new`
- `time`: time since start of VPP in seconds
- `pn`: packet number of observed QUIC packet
- `host`: server or client direction
- `spin_data`: latency estimation taking only the latency spin bit into account
- `spin_new`: does the `spin_data` contain a new estimation (0 or 1)
- `pn_spin_data`: latency estimation based on the spin bit only but rejecting reordered packets based on the packet number
- `pn_spin_new`: does the `pn_spin_new` contain a new estimation (0 or 1)
- `vec_data`: latency estimation based on the full spin signal (spin bit and VEC)
- `vec_new`: does the `vec_data` contain a new estimation (0 or 1)
- `heur_data`: latency estimation based on the spin bit only but rejecting RTT samples based on a heuristic
- `heur_new`: does the `heur_data` contain a new estimation (0 or 1)

More information can be found in our [IMC paper](https://nsg.ee.ethz.ch/fileadmin/user_upload/spinbit.pdf).

### TCP latency measurements
Header of the CSV file: `time,host,seq_num,vec_data,vec_new,single_ts_rtt_data,single_ts_rtt_new,all_ts_rtt_data,all_ts_rtt_new,vec_ne_zero_data,vec_ne_zero_new`
- `time`: time since start of VPP in seconds
- `host`: server or client direction
- `seq_num`: sequence number of observed TCP packet
- `vec_data`: latency estimation based on the full spin signal (spin bit and VEC)
- `vec_new`: does the `vec_data` contain a new estimation (0 or 1)
- `single_ts_rtt_data`: latency estimation based on one timestamp per RTT
- `single_ts_rtt_new`: does the `single_ts_rtt_data` contain a new estimation (0 or 1)
- `all_ts_rtt_data`: latency estimation based on every available timestamp value
- `all_ts_rtt_new`: does the `all_ts_rtt_data` contain a new estimation (0 or 1)
- `vec_ne_zero_data`: latency estimation based on the full spin signal (spin bit and VEC) taking every non-zero VEC value into account
- `vec_ne_zero_new`: does the `vec_ne_zero_data` contain a new estimation (0 or 1)

### PLUS latency measurements
Header of the CSV file: `time,host,#pkt,psn,pse,cat,psn_pse_data,psn_pse_new`
- `time`: time since start of VPP in seconds
- `host`: server of client directions
- `#pkt`: number of packet in PLUS flow
- `psn`: Packet Serial Number of the observed PLUS packet
- `pse`: Packet Serial Echo of the observed PLUS packet
- `cat`: Connection and Association Token of the observed PLUS packet
- `psn_pse_data`: latency estimation based on the PSN and PSE
- `psn_pse_new`: does the `psn_pse_data` contain a new estimation (0 or 1)

More information can be found in our [PLUS paper](https://nsg.ee.ethz.ch/fileadmin/user_upload/CNSM_2017.pdf).
