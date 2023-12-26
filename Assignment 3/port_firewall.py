# firewall using port number

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib.packet import ether_types

#defining the ryu application as a subclass of app_manager.RyuApp

class Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_3.OFP_VERSION]

    '''__init__ called when an instance of Firewall is created.
    variables:
    self.mac_to_port -- dictionary- maps the mac add to the output port on the switch that the mac add
                                    is connected to
    '''
    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.allowed_ips = ['10.0.0.%d' % i for i in range(0, 21)]



    '''default flow entry that floods pkts to all orts except the input port'''

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #create a flow mod msg
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
                datapath= datapath,
                priority = priority,
                match = match,
                instructions = inst
        )

        #send the flow msg to the switch
        datapath.send_msg(mod)


     #defining funct to handle switch connection events
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)

    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #install a default flow entry that floods pkts to all ports except the input port
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                            ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    '''called whenever a pkt is recieved by a switch'''

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        #get the pkt and datapath objs from the event
        pkt = packet.Packet(ev.msg.data)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = ev.msg.match['in_port']
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        #blocking port
        port = 80

        # drop packet
        if pkt.get_protocol(tcp.tcp):
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt.src_port == port:
                self.logger.info("\nBlocked TCP Packet with source port %s", port)
                self.logger.info("src_mac:%s \ndst_mac:%s\n", src, dst)
                return

        if pkt.get_protocol(udp.udp):
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt.src_port == port:
                self.logger.info("\nBlocked UDP Packet with source port %s", port)
                self.logger.info("src_mac:%s \ndst_mac:%s\n", src, dst)
                return

        
        self.logger.info("packet in src_mac:%s dst_mac:%s %s", src, dst, in_port)

        #send pkt out of the appropriate port
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
                datapath = datapath,
                buffer_id = ofproto.OFP_NO_BUFFER,
                in_port = in_port ,
                actions = actions,
                data = ev.msg.data
                )
        datapath.send_msg(out)
