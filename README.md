# autumn2023
SDN &amp; NFV CO520/CS638 assignments

**Question 1:-**
Write a ryu controller code such that it prints ARP header information by the switch after h1 pings h2.
Print 1.) ARP source & destination MAC 2.) ARP source & destination IP

**Question 2:-**
Write a ryu controller code for the topology as shown below: create a l2 firewall, i.e. block MAC addresses such that h1 should not be able to ping h3. Rest of the hosts should be able to ping each other:

h1-->h2 (Allow)
h1-->h3 (Dont Allow)
h1-->h4 (Allow)

**Question 3:-**
Write a ryu controller code for any topology such that communication is not available on a certain port. For e.g. in the following topology: if: port 50,000 is blocked then if h1 tries to send tcp packets to h2 on port 50,000 then, it should not allowed.

**Question 7:-**
Implementing a pipeline using OpenFlow v1.3 with Ryu controller and Mininet. The objective is to create a network topology where all hosts are connected to a switch (s1). The pipeline involves two tables: table0 for blocking packets based on IP addresses and table1 for blocking packets based on TCP ports.
