Assignment 7:-
Write a ryu controller code for the topology as shown below:

				controller
			      /  /  /\  \  \
			     /  /  /  \  \  \
			    h1 h2 h3   h4 h5 h6

It implements openflow v1.3 and creates two level firewall using two tables where first table will block a packet by source ip and the second table will block the packet by TCP port.

h1-->h2 (block by IP)

h3-->h4 (block by TCP port)

h5-->h6 (ping each other)
