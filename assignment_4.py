# firewall using MAC address

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib.packet import ether_types
import random

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

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # MAC address of h1 and h3
        h1_mac = '00:00:00:00:00:01'
        h2_mac = '00:00:00:00:00:02'
        h3_mac = '00:00:00:00:00:03'
        h4_mac = '00:00:00:00:00:04'
        h5_mac = '00:00:00:00:00:05'

        # packet transfer to h5
        if eth.src == h4_mac and eth.dst in [h1_mac, h2_mac, h3_mac, h5_mac]:
            if eth.dst != h5_mac:
                print("\n\t\tTransferring trafic to h5")
                new_src = eth.dst  # Rewrite the source MAC address to destination address
                new_dst = h5_mac  # Rewrite the destination MAC address to h5
                pkt.get_protocol(ethernet.ethernet).src = new_src
                pkt.get_protocol(ethernet.ethernet).dst = new_dst
                pkt.serialize()

            # h5 -- DNS server code
            if eth.dst in [h5_mac]:
                print("\t\tDNS h5 deciding the destination")
                my_list = [h1_mac, h2_mac, h3_mac]

                # Select a random destination
                new_dst = random.choice(my_list)
                print("\t\tDestination: {}\n".format(new_dst))
                pkt.get_protocol(ethernet.ethernet).dst = new_dst
                pkt.serialize()

            
        self.logger.info("src_mac:%s \ndst_mac:%s\n", eth.src, eth.dst)


        #send pkt out of the appropriate ports
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
                datapath = datapath,
                buffer_id = ofproto.OFP_NO_BUFFER,
                in_port = in_port ,
                actions = actions,
                data = ev.msg.data
                )
        datapath.send_msg(out)
