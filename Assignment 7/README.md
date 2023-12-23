# Assignment 7
**Use Openflow v1.3 to implement a pipeline.**

Implementing a pipeline using OpenFlow v1.3 with Ryu controller and Mininet. The objective is to create a network topology where all hosts are connected to a switch (s1). The pipeline involves two tables: table0 for blocking packets based on IP addresses and table1 for blocking packets based on TCP ports.

## Topology:
switch: s1
hosts: h1, h2, h3, h4, h5, h6, h7

## Pipeline Steps:

1. Blocking IP Addresses (table0):
In table0, the pipeline blocks packets based on specified IP addresses.
Ryu controller configures table0 to match and block specific IP addresses.

2. Blocking TCP Ports (table1):
After passing through table0, the packet proceeds to table1.
Table1 is configured by the Ryu controller to block packets based on specified TCP ports.

3. Output:
Packets that have successfully passed through both table0 and table1 are allowed to proceed and are eventually output.
