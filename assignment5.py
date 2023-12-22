#!/usr/bin/env python

import time
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch


def run():
    setLogLevel('info')
    net = Mininet()

    r1 = net.addHost('r1')
    r2 = net.addHost('r2')
    r3 = net.addHost('r3')

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')

    net.addLink(r1, r2)
    net.addLink(r1, r3)
    net.addLink(r2, h1)
    net.addLink(r3, h2)
    net.addLink(r3, h3)
    net.addLink(r3, h4)


    r2.cmd('h1 vconfig add h1-eth0 100')
    r2.cmd('h2 vconfig add h2-eth0 200')
    r3.cmd('h3 vconfig add h3-eth0 100')
    r3.cmd('h4 vconfig add h4-eth0 200')

    r2.cmd('h1 route del -net 10.0.0.0 netmask 255.0.0.0')
    r2.cmd('h2 route del -net 10.0.0.0 netmask 255.0.0.0')
    r3.cmd('h3 route del -net 10.0.0.0 netmask 255.0.0.0')
    r3.cmd('h4 route del -net 10.0.0.0 netmask 255.0.0.0')

    r2.cmd('h1 ifconfig h1-eth0.100 10.0.0.1')
    r2.cmd('h2 ifconfig h2-eth0.200 10.0.0.2')
    r3.cmd('h3 ifconfig h3-eth0.100 10.0.0.3')
    r3.cmd('h4 ifconfig h4-eth0.200 10.0.0.4')
    
    net.start()

    CLI(net)

    net.stop()
    return


if __name__ == '__main__':
    run()