from xml.dom.minicompat import NodeList
import requests
import os.path
from zipfile import ZipFile
import xml.etree.ElementTree as ET
import sys, time




from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink










class iomt_topo:
    def __init__(self):
        self.controller_type = RemoteController
        self.controller_ip = '127.0.0.1'
        self.controller_port = 6653
        self.xterms = True
        self.run_topo()
    
    
    
    
    def run_topo(self):    

        def buildNetwork():
            net = Mininet(topo = None, build = False, ipBase = '10.0.0.0/8')


            info( '*** Adding controller\n' )
            c0 = net.addController(name = 'c0', controller = self.controller_type, protocol = 'tcp', ip = self.controller_ip, port = self.controller_port)
            

            info( '*** Adding switches\n')
            rpy1 = net.addSwitch('rpy1', dpid='0000000000001111', cls=OVSKernelSwitch)
            phy1 = net.addSwitch('phy1', dpid='0000000000002222', cls=OVSKernelSwitch)
            info( '*** Add hosts\n')
            h1 = net.addHost('h1', cls=Host, mac="00:00:00:00:11:11")
            h2 = net.addHost('h2', cls=Host, mac="00:00:00:00:11:12")
            h3 = net.addHost('h3', cls=Host, mac="00:00:00:00:11:13")
            h4 = net.addHost('h4', cls=Host, mac="00:00:00:00:11:14")
            h5 = net.addHost('h5', cls=Host, mac="00:00:00:00:11:15")
            h6 = net.addHost('h6', cls=Host, mac="00:00:00:00:11:16")
            net.addLink(rpy1, phy1, cls = TCLink)
            net.addLink(h1,rpy1,cls = TCLink)
            net.addLink(h2,rpy1,cls = TCLink)
            net.addLink(h3,rpy1,cls = TCLink)
            
            net.addLink(h4,phy1,cls = TCLink)
            net.addLink(h5,phy1,cls = TCLink)
            net.addLink(h6,phy1,cls = TCLink)


            info( '*** Starting network\n')
            net.build()


            info( '*** Starting controller\n')
            for controller in net.controllers:
                controller.start()

            info( '*** Starting switches\n')
            rpy1.start([c0])    
            phy1.start([c0])


            info( '\n*** Post configure switches and hosts\n')
            phy1.cmdPrint('sudo ovs-vsctl set port phy1-eth1 qos=@defaultqos -- --id=@defaultqos create qos type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2 -- --id=@q0 create queue other-config:min-rate=1000000000 other-config:max-rate=1000000000 -- --id=@q1 create queue other-config:max-rate=20000000 -- --id=@q2 create queue other-config:max-rate=1000000 other-config:min-rate=1000000')
            CLI(net)
            net.stop()
            
            return net

        setLogLevel('info')        
        buildNetwork()
        info('\n')


if __name__ =="__main__":
    iomt_topo()
