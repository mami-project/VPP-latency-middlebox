# A cloud-init script for the VPP latency middlebox emulator #

This directory contains the cloud-init script to instantiate the middlebox emulator in a cloud-init compatible virtualisation environment.

## Customisation ##

At the end of the file, you have a commented SSH section. Uncomment and insert your *public* SSH key where indicated. This will allow you to SSH into the box with the default (ubuntu) user directly. Depending on the virtualisation environment this may or may not be desirable. Check with the documentation of your virtualisation environment.

## Checking the VM ##

Once your virtualisation environment creates the VM instance, give it aprox. 2 minutes to download, install and start the VPP latency plugin. SSH into the VM with the default (ubuntu) user.

You can check that the plugin has been correctly installed using the command:

`sudo service vpp status`
