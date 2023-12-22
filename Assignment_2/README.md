Question 2-->
Write a ryu controller code for the topology as shown below:
	
				controller
				/  /  \  \
			       /  /    \  \
			      h1 h2    h3 h4

create a l2 firewall, i.e. block MAC addresses such that h1 should not be able to ping h3. Rest of the hosts should be able to ping each other, i.e.
	

h1-->h2 ✅

h1-->h3 ❌ 

h1-->h4 ✅
