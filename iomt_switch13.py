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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

iptos_be = 0x00
iptos_ef = 0x2E
iptos_af21 = 0x12
iptos_af31 = 0x1A
iptos_af41 = 0x22


rpy1_dpid = "0000000000001111"
phy1_dpid = "0000000000002222"

TABLE_0 = 0
TABLE_1 = 1



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.sensor_macaddr = self.load_macs("sensors.txt")
        self.device_macaddr = self.load_macs("devices.txt")
        self.mac_to_dscp = {}
        self.dscp_to_meterid = {iptos_be: None, iptos_ef: 1, iptos_af21: 2, iptos_af31: 3, iptos_af41: 4}

    def load_macs(self, filename):
        f = open(filename, "r")
        raw = f.read()
        macs = raw.split("\n")
        f.close()
        return macs



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Packet in messages disabled")

        self.logger.info("Creating Meters")
        self.create_meter(datapath=datapath, rate=None, meter_id=2)             #meter for af21 
        self.create_meter(datapath=datapath, rate=None, meter_id=3)             #meter for af31
        self.create_meter(datapath=datapath, rate=None, meter_id=4)             #meter for af41


        if datapath.id == rpy1_dpid:
            inst = [parser.OFPInstructionGotoTable(TABLE_1)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=TABLE_0, priority = 1, instructions = inst)
            datapath.send_msg(mod)
        elif datapath.id == phy1_dpid:
            pass
        else:
            return
        

    def create_meter(self, datapath, rate, meter_id):
        bands = []
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        bands.append(parser.OFPMeterBandDscpRemark(rate = rate, prec_level = 1))
        metermod = parser.OFPMeterMod(datapath=datapath, command = ofproto.OFPMC_ADD, flags = ofproto.OFPMF_KBPS, meter_id = meter_id, bands = bands)
        datapath.send_msg(metermod)
        self.logger.info("New Meter Created on Switch: %s with ID: %s", datapath.id, meter_id)
        return

    def create_table_zero(self, datapath, tableid):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if tableid == TABLE_0:
            inst = [parser.OFPInstructionGotoTable(TABLE_1)]

    def add_flow(self, datapath, tableid, priority, match, actions, buffer_id=None, meterband = None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if meterband == None:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions), parser.OFPInstructionMeter(meterband,ofproto.OFPIT_METER)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, table_id=tableid, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=tableid, 
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # install a flow to avoid packet_in next time        
        if out_port != ofproto.OFPP_FLOOD:
            if dpid == rpy1_dpid:
                ip_dscp = self.get_dscp(macaddr=src)
                self.mac_to_dscp[src] = ip_dscp
                meterband = None if ip_dscp == iptos_ef else self.get_meterband(ip_dscp)
                match_table0 = parser.OFPMatch(in_port=in_port, eth_dst = dst, eth_src = src)
                actions_table0 = [parser.OFPActionSetField(ip_dscp=ip_dscp)]
                self.add_flow(datapath=datapath, table_id = TABLE_0, priority=1000, match=match_table0, actions = actions_table0, buffer_id=(msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None), meterband=None)
                
                
                match_table1 = parser.OFPMatch(in_port=in_port, eth_dst = dst, eth_src = src, ip_dscp = ip_dscp)
                actions_table1 = [parser.OFPActionOutput(out_port)]

                self.add_flow(datapath=datapath, priority=1000, tableid=TABLE_1, match=match_table1, actions = actions_table1, buffer_id=(msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None), meterband=None)
            elif dpid == phy1_dpid:
                pass
            else:
                return



        # actions = [parser.OFPActionOutput(out_port)]



            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def get_dscp(self, macaddr):
        if macaddr in self.sensor_macaddr:
            return iptos_ef
        elif macaddr in self.device_macaddr:
            return iptos_af41
        else:
            return iptos_be
        

    def get_meterband(self, ip_dscp):

