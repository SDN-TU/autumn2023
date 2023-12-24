Question 5-->
Write a a topology with 4 host machines, such that 2 host are on one VLAN id(say 100), while the other two are on another VLAN id(say 200)

				controller
				/  /  \  \
			       /  /    \  \
			      h1 h2    h3 h4
			 (VLAN 100)	(VLAN 200)

Then if h1 tries to ping h3 or h4 it will not ping, same goes for h2.
