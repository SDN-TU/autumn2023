import random
from ryu.lib import dpid as dpid_lib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac as mac_lib
from ryu.lib import ip as ip_lib
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, icmp
from ryu.ofproto import ether, inet


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        self.serverIP1="10.0.0.1"
        self.serverMac1="00:00:00:00:00:01"
        self.serverIP2="10.0.0.2"
        self.serverMac2="00:00:00:00:00:02"
        self.serverIP3="10.0.0.3"
        self.serverMac3="00:00:00:00:00:03"
        
        self.serverCount=1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    #Generate ARP reply packet for ARP request 
    def arpReplyGenerate(self, dstMac, dstIp):
        srcMac = "11:22:33:ab:cd:ef"
        srcIp = "10.0.0.5"

        packetReply = packet.Packet()
        etherReply = ethernet.ethernet(dstMac, srcMac,0x0806)
        arpReply = arp.arp(1,0x0800,6,4,2,srcMac,srcIp,dstMac,dstIp)
        packetReply.add_protocol(etherReply)
        packetReply.add_protocol(arpReply)
        packetReply.serialize()

        return packetReply
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):    	 
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
       
  

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        #ARP Reply handling
        if(eth.ethertype==0x0806):
           
            arpContents=pkt.get_protocols(arp.arp)[0]
            if((arpContents.dst_ip=="10.0.0.5")and(arpContents.opcode==1)):
                
                packetReply=self.arpReplyGenerate(arpContents.src_mac,arpContents.src_ip)
                actionsServer=[parser.OFPActionOutput(in_port)]
                arpServer=parser.OFPPacketOut(datapath=datapath,in_port=ofproto.OFPP_ANY,data=packetReply.data,actions=actionsServer,buffer_id=0xffffffff)                
                datapath.send_msg(arpServer)
            return
        
        if(self.serverCount==1):
            serverIP=self.serverIP1
            serverMac=self.serverMac1
        elif(self.serverCount==2):
            serverIP=self.serverIP2
            serverMac=self.serverMac2
        elif(self.serverCount==3):
            serverIP=self.serverIP3
            serverMac=self.serverMac3  
            
     

        if(eth.ethertype==0x0800):
            ipContents=pkt.get_protocols(ipv4.ipv4)[0]
            if((ipContents.dst=="10.0.0.5")and(ipContents.proto==0x06)):
                tcpContents=pkt.get_protocols(tcp.tcp)[0]
                
                
                #TCP Host to Server
       
                match1=parser.OFPMatch(in_port=in_port,eth_type=eth.ethertype,eth_src=eth.src,eth_dst=eth.dst,ip_proto=ipContents.proto,
                ipv4_src=ipContents.src,ipv4_dst=ipContents.dst,tcp_src=tcpContents.src_port,tcp_dst=tcpContents.dst_port)


                actions1=[parser.OFPActionSetField(ipv4_src="10.0.0.5"),parser.OFPActionSetField(eth_dst=serverMac),
                parser.OFPActionSetField(ipv4_dst=serverIP),parser.OFPActionOutput(self.serverCount)]

                ipInst1=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions1)] 
                cookie1=random.randint(0, 0xffffffffffffffff)

                
                flowMod1=parser.OFPFlowMod(datapath=datapath,match=match1,idle_timeout=7,instructions=ipInst1,buffer_id=msg.buffer_id,cookie=cookie1)
                
                datapath.send_msg(flowMod1)
                
                #TCP Server to Host
                
                match2=parser.OFPMatch(self.serverCount,eth_type=eth.ethertype,eth_src=serverMac,eth_dst="11:22:33:ab:cd:ef",ip_proto=ipContents.proto,
                ipv4_src=serverIP,ipv4_dst="10.0.0.5",tcp_src=tcpContents.dst_port,tcp_dst=tcpContents.src_port)


                actions2=[parser.OFPActionSetField(eth_src="11:22:33:ab:cd:ef"),parser.OFPActionSetField(ipv4_src="10.0.0.5"),parser.OFPActionSetField(eth_dst=eth.src),
                parser.OFPActionSetField(ipv4_dst=ipContents.src),parser.OFPActionOutput(in_port)]

                ipInst2=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions2)] 

                cookie2=random.randint(0, 0xffffffffffffffff)


                flowMod2=parser.OFPFlowMod(datapath=datapath,match=match2,idle_timeout=7,instructions=ipInst2,cookie=cookie2)  
                
                datapath.send_msg(flowMod2)         
                

        #Server Count increment

        self.serverCount+=1
        if(self.serverCount>3):
            self.serverCount=1 


    
