# Assignment 4

Design a Ryu controller to control the traffic flow in a network topology consisting of a switch (s1) connected to hosts h1, h2, h3, h4, and h5. The objective is to redirect ping traffic initiated by h4 through h5, where h5 determines the final destination. The traffic should flow from h4 to h5 first, and then h5 decides the destination (h1, h2, or h3) before allowing the traffic to reach the chosen destination.

## Topology:
switch: s1
hosts: h1, h2, h3, h4, h5

### Specific to my code
- The code ensures that traffic initiated by h4 is routed through h5, which randomly determines the final destination.
- Direct traffic to h1, h2, or h3 is send to h5 first.
