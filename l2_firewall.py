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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib.packet import ether_types


class FirewallL2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def load_mac_to_block(self):
        f = open ("mactoblock.txt", "r")
        raw = f.read()
        macs = raw.split("\n")
        f.close()
        return macs

    def __init__(self, *args, **kwargs):
        super(FirewallL2Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_block = self.load_mac_to_block()
        self.logger.info("Loading MAC Blocklist:\n%s", self.mac_to_block)

    def add_flow(self, datapath, in_port, type, dst, src, actions):
        ofproto = datapath.ofproto


        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_type = type,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
        return

    def get_opcode_type(self, arp_opcode):
        switcher = {
            1 : "ARP_REQUEST",
            2 : "ARP_REPLY",
            3 : "ARP_REV_REQUEST",
            4 : "ARP_REV_REPLY"
        }
        return switcher.get(arp_opcode, "ERROR")
    

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

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            arpmac_src = arp_pkt.src_mac
            arpmac_dst = arp_pkt.dst_mac
            arpip_src = arp_pkt.src_ip
            arpip_dst = arp_pkt.dst_ip
            arp_opcode = arp_pkt.opcode
            self.logger.info("\nARP Packet IN:\nARP Type: %s", self.get_opcode_type(arp_opcode))
            self.logger.info("MAC SRC: %s, MAC DST: %s, IP SRC: %s, IP DST: %s\n\n", arpmac_src, arpmac_dst, arpip_src, arpip_dst)

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


            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.add_flow(datapath, msg.in_port, ether_types.ETH_TYPE_ARP, dst, src, [datapath.ofproto_parser.OFPActionOutput(out_port)])
                self.forward_packet(msg, out_port)

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                if dst not in self.mac_to_block:
                    self.add_flow(datapath, msg.in_port, ether_types.ETH_TYPE_IP, dst, src, [datapath.ofproto_parser.OFPActionOutput(out_port)])
                    self.forward_packet(msg, out_port)
            
                else:
                    self.add_flow(datapath, msg.in_port, ether_types.ETH_TYPE_IP, dst, src, [])

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