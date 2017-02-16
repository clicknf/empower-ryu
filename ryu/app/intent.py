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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto.ofproto_v1_0_parser import OFPMatch
from collections import OrderedDict
from ryu.app.wsgi import WSGIApplication
from threading import Lock
import traceback

from ryu.app.rest_intent import IntentController
from ryu.app.rest_intent import dpid_to_empower

OFP_LW_PRIORITY = 100
OFP_RULE_PRIORITY = 200
BASE_HEX = 16


class LSwitch:
    def __init__(self, datapath):

        self._dp = datapath
        self._ofproto = datapath.ofproto
        self._ofproto_parser = self._dp.ofproto_parser
        self._hosts = {}

    def get_dp(self):
        return self._dp

    def get_dp_id(self):
        return self._dp.id

    # update or learn a new host
    def update_host(self, mac, port):

        if mac in self._hosts and self._hosts[mac] != port:
            self.delete_host_rules(mac)

        self._hosts[mac] = port

    def get_host_port(self, mac):
        return self._hosts.get(mac)

    def delete_host(self, mac):

        if mac in self._hosts:
            del self._hosts[mac]

    def delete_host_rules(self, mac):

        match = self._ofproto_parser.OFPMatch(dl_src=mac)
        mod = self._ofproto_parser.OFPFlowMod(
            datapath=self._dp,
            match=match,
            cookie=0,
            command=self._ofproto.OFPFC_DELETE)

        self._dp.send_msg(mod)

        match = self._ofproto_parser.OFPMatch(dl_dst=mac)
        mod = self._ofproto_parser.OFPFlowMod(
            datapath=self._dp,
            match=match,
            cookie=0,
            command=self._ofproto.OFPFC_DELETE)

        self._dp.send_msg(mod)

    def packet_out(self, msg, out_port):

        actions = [self._dp.ofproto_parser.OFPActionOutput(out_port)]
        data = None

        if msg.buffer_id == self._ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = self._dp.ofproto_parser.OFPPacketOut(
            datapath=self._dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)

        self._dp.send_msg(out)

    def add_out_rule(self, src, dst, in_port, out_port,
                     priority=OFP_LW_PRIORITY):

        actions = [self._dp.ofproto_parser.OFPActionOutput(out_port)]
        match = self._ofproto_parser.OFPMatch(
            dl_src=haddr_to_bin(src),
            dl_dst=haddr_to_bin(dst),
            in_port=in_port)

        mod = self._ofproto_parser.OFPFlowMod(
            datapath=self._dp,
            match=match,
            cookie=0,
            command=self._ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            priority=priority,
            flags=self._ofproto.OFPFF_SEND_FLOW_REM,
            actions=actions)

        self._dp.send_msg(mod)


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

    return dist, prev


class Intent(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):

        super(Intent, self).__init__(*args, **kwargs)

        self.rules = {}
        self.lvnf_info = OrderedDict()
        self.LSwitches = {}
        self.mutex = Lock()

        wsgi = kwargs['wsgi']
        wsgi.register(IntentController, {'intent_app': self})

    def _get_nexthop_port(self, src_dpid, dst_dpid):
        sws_list = get_switch(self, None)
        sws = [switch.dp.id for switch in sws_list]

        links_list = get_link(self, None)

        links = []
        for link in links_list:
            links.append({'src': link.src.dpid,
                          'dst': link.dst.dpid,
                          'port': link.dst.port_no})

        _, prev = dijkstra(sws, links, dst_dpid)

        if prev[src_dpid] is None:
            return None
        else:
            return prev[src_dpid][1]

    def _compile_rule(self, rule):
        """Compile rule."""

        _, preds = self._get_nexthop_port()

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
                    priority=OFP_RULE_PRIORITY, actions=actions)

                rule.flow_mods.append(mod)
                # datapath.send_msg(mod)

    def _find_host_dpid(self, mac):

        dpid = None
        dp_host_port = None

        for sw_id in self.LSwitches:

            hosts = get_host(self, sw_id)
            target_host = [host for host in hosts
                           if host.mac == mac.lower()]

            if len(target_host) > 0:

                # be sure that Ryu report this host on only one dp and port
                assert dpid is None
                assert dp_host_port is None
                assert len(target_host) == 1
                target_host = target_host[0]
                dpid = sw_id
                dp_host_port = target_host.port.port_no

        return dpid, dp_host_port

    def update_rule(self, uuid, rule):
        """Update VNF Link."""

        if not rule.equal_to(self.rules[uuid]):

            self.remove_rule(uuid)
            self.add_rule(rule)

    def add_rule(self, rule):
        """Add VNF link."""

        try:

            self.mutex.acquire()

            self.logger.info('adding rule: %s' % rule.uuid)
            self.logger.info(rule.to_jsondict())

            mac = rule.hwaddr

            # delete all rules and unlearn host
            for switch in self.LSwitches.values():
                # fixme, why dst?
                switch.delete_host_rules(mac)
                switch.delete_host(mac)

            #self._compile_rule(rule)

            self.rules[rule.uuid] = rule

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    def remove_rule(self, uuid=None):
        """Remove VNF link."""

        try:

            self.mutex.acquire()
            print('removing rule: %s' % uuid)

            if uuid:
                del self.rules[uuid]
            else:
                for uuid in list(self.rules):
                    del self.rules[uuid]

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
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

        dst = eth.dst.upper()
        src = eth.src.upper()

        if int(dst.split(':')[0], BASE_HEX) & 1 \
                and dst != "FF:FF:FF:FF:FF:FF" \
                and dst != "00:00:00:00:00:00":
            # ignore multicast packets, but allow broadcast packets
            return

        try:

            self.mutex.acquire()

            dpid = datapath.id

            # fixme, a switch may reconnect
            if dpid in self.LSwitches:

                switch = self.LSwitches[dpid]

                if not switch.get_dp().is_active:

                    # switch has restarted
                    del self.LSwitches[dpid]
                    switch = LSwitch(datapath)
                    self.LSwitches[dpid] = switch

            else:
                switch = LSwitch(datapath)
                self.LSwitches[dpid] = switch

            # for both src and dst check whether these are controlled by Empower
            empower_src_list = [rule for rule in self.rules.values()
                                if rule.hwaddr == src]
            assert len(empower_src_list) <= 1
            empower_src = None
            if len(empower_src_list) == 1:
                empower_src = empower_src_list[0]

            empower_dst_list = [rule for rule in self.rules.values()
                                if rule.hwaddr == dst]
            assert len(empower_dst_list) <= 1
            empower_dst = None
            if len(empower_dst_list) == 1:
                empower_dst = empower_dst_list[0]

            # in case both src and dst are unknown to Empower, proceed with
            # regular learning switch
            if empower_src is None and empower_dst is None:

                # learn a mac address to avoid FLOOD next time.
                switch.update_host(src, msg.in_port)

                out_port = switch.get_host_port(dst)

                if out_port is None:
                    switch.packet_out(msg, ofproto.OFPP_FLOOD)
                else:
                    switch.add_out_rule(src, dst, msg.in_port, out_port)
                    switch.packet_out(msg, out_port)

            else:

                # either src or dst are Empower controlled,
                target_dpid, target_port = None, None

                if empower_dst is None:
                    target_dpid, target_port = self._find_host_dpid(dst)

                if empower_dst is not None:
                    target_dpid = empower_dst.dpid
                    target_port = empower_dst.port

                if target_dpid is None:

                    switch.packet_out(msg, ofproto.OFPP_FLOOD)
                    return

                nexthop_port = self._get_nexthop_port(switch.get_dp_id(),
                                                      target_dpid)

                if nexthop_port is None:
                    nexthop_port = target_port

                switch.add_out_rule(src, dst, msg.in_port, nexthop_port,
                                    priority=OFP_RULE_PRIORITY)
                switch.packet_out(msg, nexthop_port)

        except Exception:
            traceback.print_exc()
            raise
        finally:
            self.mutex.release()

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
