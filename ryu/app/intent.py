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
from ryu.app.wsgi import WSGIApplication
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app.rest_intent import IntentController
from ryu.app.rest_intent import IntentRule
from ryu.topology.event import EventSwitchEnter
from ryu.topology.api import get_switch, get_link


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
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):

        super(Intent, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.rules = {}

        wsgi = kwargs['wsgi']
        wsgi.register(IntentController, {'intent_app': self})

    def add_rule(self, rule, rule_id=None):
        """Add VNF link."""

        new_rule = IntentRule(rule, rule_id)
        self.rules[new_rule.uuid] = new_rule

        # handle hwaddr
        sws_list = get_switch(self, None)
        sws = [switch.dp.id for switch in sws_list]

        links_list = get_link(self, None)
        links = []

        for link in links_list:
            links.append({'src': link.src.dpid,
                          'dst': link.dst.dpid,
                          'port': link.dst.port_no})

        _, preds = dijkstra(sws, links, new_rule.src_dpid)

        for pred in preds:

            if not preds[pred]:
                datapath = get_switch(self, new_rule.src_dpid)[0].dp
                port = new_rule.src_port
            else:
                datapath = get_switch(self, pred)[0].dp
                port = preds[pred][1]

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(dl_dst=new_rule.hwaddr)

            # delete any rule matching the same hwaddr
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_DELETE,
                priority=200)

            datapath.send_msg(mod)

            # add new rules
            actions = [parser.OFPActionOutput(port)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD,
                priority=200, actions=actions)

            new_rule.flow_mods.append(mod)

            datapath.send_msg(mod)

        return new_rule.uuid

    def _add_flow(self, datapath, in_port, dst, actions):
        """Add new flow to the network."""

        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=in_port, dl_dst=dst)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

    @set_ev_cls(EventSwitchEnter, MAIN_DISPATCHER)
    def _switch_enter_handler(self, ev):

        datapath = ev.switch.dp
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, match=match,
                                cookie=0, command=ofproto.OFPFC_DELETE,
                                actions=[])
        datapath.send_msg(mod)

    def remove_rule(self, rule_id=None):
        """Remove VNF link."""

        if rule_id:
            self._remove_reverse_path(rule_id)
            del self.rules[rule_id]
            return

        for rule_id in self.rules.keys():
            self._remove_reverse_path(rule_id)
            del self.rules[rule_id]

    def _remove_reverse_path(self, rule_id):
        """Remove deployed rules."""

        rule = self.rules[rule_id]

        for mod in rule.flow_mods:

            datapath = mod.datapath
            ofproto = datapath.ofproto
            match = mod.match

            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_DELETE_STRICT,
                priority=200)

            datapath.send_msg(mod)

    @property
    def hwaddrs(self):
        """Get the list of hwaddres."""

        hwaddrs = set()

        for rule in self.rules.values():
            hwaddrs.add(rule.hwaddr)

        return hwaddrs

    @property
    def vnf_ports(self):
        """Get the list of vnf ports."""

        vnf_ports = set()

        for rule in self.rules.values():
            vnf_ports.add((rule.src_dpid, rule.src_port))
            if rule.dst_dpid:
                vnf_ports.add((rule.dst_dpid, rule.dst_port))

        return vnf_ports

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

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        if src not in self.hwaddrs:
            self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self._add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)

        datapath.send_msg(out)
