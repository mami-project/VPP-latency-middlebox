# Using the VPP emulator with cloud environments and OSM Release 3 #

## Cloud environments: cloud-init script for the VPP latency middlebox emulator ##

The cloud-init script to instantiate the middlebox emulator in a compatible virtualisation environments is <./vpp-lat-mb.ini>.

### Customisation ###

At the end of the file, you have a commented SSH section. Uncomment and insert your *public* SSH key where indicated. This will allow you to SSH into the box with the default (ubuntu) user directly. Depending on the virtualisation environment this may or may not be desirable. Check with the documentation of your virtualisation environment.

### Checking the VM ###

Once your virtualisation environment creates the VM instance, give it aprox. 2 minutes to download, install and start the VPP latency plugin. SSH into the VM with the default (ubuntu) user.

You can check that the plugin has been correctly installed using the command:

`sudo service vpp status`

## OSM release 3 environments ##

To deploy the VPP latency middlebox in NFV environments using [OSM Release THREE](https://osm.etsi.org/wikipub/index.php/OSM_Release_THREE), you need a VNF descriptor and a scenario descriptor. Both are provided in this directory.

### Customisation ###

As with the cloud init script, the [VNF descriptor](./vpp-cloud-init.yaml) needs to be customised. Insert your `${HOME}/.ssh/idrsa.pub` file in the key `boot-data:key-pairs:ssh-rsa` in this file.

The current configuration assumes the following interface assignments:

Interface | Functionality
----------|--------------------
eth0      | Management
eth1      | East data interface
eth2      | West data interface
