# Copyright (C) 2016 Roberto Riggio.
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
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_bin
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app.rest_intent import IntentController
from ryu.topology.event import EventSwitchEnter
from ryu.topology.api import get_switch, get_link
from ryu.ofproto.ofproto_v1_0_parser import OFPMatch
from collections import OrderedDict

OFP_LW_PRIORITY = 100
OFP_RULE_PRIORITY = 200
BASE_HEX = 16


def dijkstra(vertices, edges, source):
    """Compute minimum spanning tree."""

    if source not in vertices:
        raise ValueError("source %u not in the vertices")

    dist = {}
    prev = {}
    unvisited = []

    for vertex in vertices:
        dist[vertex] = float('inf')
        prev[vertex] = None
        unvisited.append(vertex)

    dist[source] = 0

    while unvisited:

        available = {k: v for k, v in dist.items() if k in unvisited}
        u = min(available, key=available.get)
        unvisited.remove(u)

        neighbors = [x for x in edges if x['src'] == u]

        for v in neighbors:

            alt = dist[u] + 1

            if alt < dist[v['dst']]:
                dist[v['dst']] = alt
                prev[v['dst']] = [u, v['port']]

    return (dist, prev)


class Intent(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):

        super(Intent, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.rules = {}
        self.lvnf_info = OrderedDict()

        wsgi = kwargs['wsgi']
        wsgi.register(IntentController, {'intent_app': self})

    def _compute_spanning_tree(self, ttp_dpid):
        """Compute spanning tree rooted on ttp_dpid"""

        sws_list = get_switch(self, None)
        sws = [switch.dp.id for switch in sws_list]

        links_list = get_link(self, None)

        links = []
        for link in links_list:
            links.append({'src': link.src.dpid,
                          'dst': link.dst.dpid,
                          'port': link.dst.port_no})

        dist, prev = dijkstra(sws, links, ttp_dpid)

        return (dist, prev)

    def _compile_rule(self, rule):
        """Compile rule."""

        _, preds = self._compute_spanning_tree(rule.ttp_dpid)

        for pred in preds:

            if not preds[pred]:
                datapath = get_switch(self, rule.ttp_dpid)[0].dp
                port = rule.ttp_port
            else:
                datapath = get_switch(self, pred)[0].dp
                port = preds[pred][1]

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            actions = [parser.OFPActionOutput(port)]

            for in_port in datapath.ports:

                if in_port == port:
                    continue

                if in_port == 65534:
                    continue

                rule.match['in_port'] = in_port
                match = OFPMatch(**rule.match)
                del rule.match['in_port']

                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_ADD,
                    priority=200, actions=actions)

                rule.flow_mods.append(mod)

    def _compile_rule_vlan(self, rule):
        """Compile rule."""

        _, preds = self._compute_spanning_tree(rule.ttp_dpid)

        for pred in preds:

            if not preds[pred]:
                datapath = get_switch(self, rule.ttp_dpid)[0].dp
                port = rule.ttp_port

            else:
                datapath = get_switch(self, pred)[0].dp
                port = preds[pred][1]

            parser = datapath.ofproto_parser
            actions = [parser.OFPActionVlanVid(rule.match['dl_vlan'])]
            actions.append(parser.OFPActionOutput(port))

            for in_port in datapath.ports:

                if in_port == port:
                    continue

                if in_port == 65534:
                    continue

                if pred == rule.stp_dpid and in_port == rule.stp_port:
                    match = OFPMatch(in_port=in_port, dl_src=rule.match['dl_src'])
                    self.update_flow_mod(datapath, rule, match, actions)
                    continue

                elif pred == rule.ttp_dpid:

                    if len(self.lvnf_info) == 1:
                        if rule.stp_dpid != None:
                            rule.match['in_port'] = in_port
                            match = OFPMatch(**rule.match)
                            del rule.match['in_port']
                        else:
                            match =  OFPMatch(in_port=in_port, dl_src=rule.match['dl_src'])

                    else:
                        #prev = len(self.lvnf_info) - 2
                        match = OFPMatch(in_port=self.lvnf_info.values()[0]['ttp_port'],
                                         dl_src=rule.match['dl_src'], dl_vlan=self.lvnf_info.values()[0]['dl_vlan'],
                                         dl_type=rule.match['dl_type'], nw_proto=rule.match['nw_proto'])

                    self.update_flow_mod(datapath, rule, match, actions)
                    continue

                else:
                    match = OFPMatch(dl_src=rule.match['dl_src'], dl_vlan=rule.match['dl_vlan'])
                    self.update_flow_mod(datapath, rule, match, actions)

    def update_flow_mod(self, datapath, rule, match, actions):

        ofproto = datapath.ofproto
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD,
            priority=200, actions=actions)

        rule.flow_mods.append(mod)

    def update_rule(self, uuid, rule):
        """Update VNF Link."""

        self.remove_rule(uuid)
        self.add_rule(rule)

    def add_rule(self, rule):
        """Add VNF link."""

        try:
            rule.match['dl_vlan']
        except:
            self._compile_rule(rule)
        else:
            self.lvnf_info[rule.uuid] = {'dl_vlan': rule.match['dl_vlan'], 'ttp_port': rule.ttp_port}
            self._compile_rule_vlan(rule)

        for flow_mod in rule.flow_mods:
            datapath = flow_mod.datapath
            datapath.send_msg(flow_mod)

        self.rules[rule.uuid] = rule

    def remove_rule(self, uuid=None):
        """Remove VNF link."""

        if uuid:
            self._remove_reverse_path(uuid)
            del self.lvnf_info[uuid]
            del self.rules[uuid]

            return

        for uuid in list(self.rules):
            self._remove_reverse_path(uuid)
            del self.rules[uuid]
            del self.lvnf_info[uuid]

    def _remove_reverse_path(self, uuid):
        """Remove deployed rules."""

        rule = self.rules[uuid]

        for mod in rule.flow_mods:

            datapath = mod.datapath
            ofproto = datapath.ofproto
            match = mod.match

            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_DELETE_STRICT,
                priority=OFP_RULE_PRIORITY)

            datapath.send_msg(mod)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore IPV6 Packets
            return

        dst = eth.dst
        src = eth.src

        if int(dst.split(':')[0], BASE_HEX) & 1 and dst != "ff:ff:ff:ff:ff:ff":
            # ignore multicast packets
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

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
