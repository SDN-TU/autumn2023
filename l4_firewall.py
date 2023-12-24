# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ether_types, ethernet, ipv4, tcp, udp, in_proto


class FirewallL4Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def load_port_to_block(self):
        f = open ("porttoblock.txt", "r")
        raw = f.read()
        macs = raw.split("\n")
        f.close()
        macs_int = []
        for i in macs:
            macs_int.append(int(i))
        return macs_int

    def __init__(self, *args, **kwargs):
        super(FirewallL4Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_to_block = self.load_port_to_block()
        self.logger.info("Loading L4 PORT Blocklist:\n%s", self.port_to_block)

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto


        # match = datapath.ofproto_parser.OFPMatch(
        #     in_port=in_port, dl_type = eth_type,
        #     dl_dst=haddr_to_bin(ipv4_dst), dl_src=haddr_to_bin(ipv4_src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
        return


    

    def forward_packet(self, msg, out_port):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        data = None
        
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if msg.buffer_id is not ofproto.OFP_NO_BUFFER:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)] if out_port else []   
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=actions, data=data)
            datapath.send_msg(out)

        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto 
                if protocol != in_proto.IPPROTO_TCP:
                    match = parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol)
                    self.add_flow(datapath=datapath, match=match, actions = actions)
                    self.forward_packet(msg, out_port)

                else:
                    t = pkt.get_protocol(tcp.tcp)
                    tcp_src = t.src_port
                    tcp_dst = t.dst_port
                    if tcp_src in self.port_to_block or tcp_dst in self.port_to_block:
                        self.logger.info("Destination Port %s Blocked", tcp_dst)
                        match = parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, tp_src = t.src_port, tp_dst = t.dst_port, nw_proto=protocol)
                        self.add_flow(datapath=datapath, match=match, actions = [])
                    else:
                        match = parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, tp_src = t.src_port, tp_dst = t.dst_port, nw_proto=protocol)
                        self.add_flow(datapath=datapath, match=match, actions = actions)
                        self.forward_packet(msg, out_port)
            else:
                match = parser.OFPMatch(in_port=msg.in_port, dl_type = ether_types.ETH_TYPE_ARP, dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))
                self.add_flow(datapath=datapath, match = match, actions = actions)
                self.forward_packet(msg, out_port)

        else:
            out_port = ofproto.OFPP_FLOOD
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.forward_packet(msg, out_port)



    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)