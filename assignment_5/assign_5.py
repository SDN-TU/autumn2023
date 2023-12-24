from mininet.topo import Topo
from mininet.node import Host
class VLANHost(Host):
    "Host connected to VLAN interface"

    # pylint: disable=arguments-differ
    def config( self, vlan=100, **params ):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""

        r = super( VLANHost, self ).config( **params )

        intf = self.defaultIntf()
        # remove IP from default, "physical" interface
        self.cmd( 'ifconfig %s inet 0' % intf )
        # create VLAN interface
        self.cmd( 'vconfig add %s %d' % ( intf, vlan ) )
        # assign the host's IP to the VLAN interface
        self.cmd( 'ifconfig %s.%d inet %s' % ( intf, vlan, params['ip'] ) )
        # update the intf name and host's intf map
        newName = '%s.%d' % ( intf, vlan )
        # update the (Mininet) interface to refer to VLAN interface name
        intf.name = newName
        # add VLAN interface to host's name to intf map
        self.nameToIntf[ newName ] = intf

        return r  
class MyTopo( Topo ):  
    "Simple topology example."
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        Host1 = self.addHost( 'h1' , mac='00:00:00:00:00:01', cls=VLANHost, vlan=100)
        Host2 = self.addHost( 'h2' , mac='00:00:00:00:00:02', cls=VLANHost, vlan=100)
        Host3 = self.addHost( 'h3' , mac='00:00:00:00:00:03', cls=VLANHost, vlan=200)
        Host4 = self.addHost( 'h4' , mac='00:00:00:00:00:04', cls=VLANHost, vlan=200)
        #Host5 = self.addHost( 'h5' , mac='00:00:00:00:00:05')
        Switch1 = self.addSwitch('s1')
        # Add links
        self.addLink( Host1, Switch1 )
        self.addLink( Host2, Switch1 )
        self.addLink( Host3, Switch1 )
        self.addLink( Host4, Switch1 )
        #self.addLink( Host5, Switch1 )
topos = { 'mytopo': ( lambda: MyTopo() ) } 
