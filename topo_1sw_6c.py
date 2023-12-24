#linear switch mininet custom topology


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI 
from mininet.node import RemoteController

class SingleSwitchTopo(Topo):
	def build(self):
		
		s1 = self.addSwitch('s1', dpid='0000000000000001')

		h1 = self.addHost('h1',mac="00:00:00:00:00:01", ip="10.0.0.1/8")
		h2 = self.addHost('h2',mac="00:00:00:00:00:02", ip="10.0.0.2/8")
		h3 = self.addHost('h3',mac="00:00:00:00:00:03", ip="10.0.0.3/8")
		h4 = self.addHost('h4',mac="00:00:00:00:00:04", ip="10.0.0.4/8")
		h5 = self.addHost('h5',mac="00:00:00:00:00:05", ip="10.0.0.5/8")
		h6 = self.addHost('h6',mac="00:00:00:00:00:06", ip="10.0.0.6/8")


		self.addLink(h1,s1)
		self.addLink(h2,s1)
		self.addLink(h3,s1)
		self.addLink(h4,s1)
		self.addLink(h5,s1)
		self.addLink(h6,s1)


if __name__ == "__main__":
	setLogLevel("info")
	topo = SingleSwitchTopo()
	c1 = RemoteController('c1', ip='127.0.0.1')
	net = Mininet(topo=topo, controller=c1)
	net.start()
	CLI(net)
	net.stop()
