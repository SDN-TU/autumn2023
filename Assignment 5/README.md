Assignment 5:-
Write a a topology with 4 host such that 2 host are on one VLAN id(VLAN id:-100), while the other 2 hosts are on another VLAN id(VLAN id:-200)

				controller
				/  /  \  \
			       /  /    \  \
			      h1 h2    h3 h4
		       (VLAN id:-100) (VLAN id:-200)

Then if h1 tries to ping h3 or h4 it will not be allowed, same goes for h2. But h1 can ping h2 and h3 can ping h4. 
