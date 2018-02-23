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
from ryu.lib.packet import vlan
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host
from ryu.ofproto import ofproto_v1_0
from collections import OrderedDict
from ryu.app.wsgi import WSGIApplication
from threading import Lock
import traceback

from ryu.app.rest_intent import IntentController
from ryu.app.rest_intent import dpid_to_empower

OFP_LW_PRIORITY = 100
OFP_RULE_PRIORITY = 200
OFP_TUNNEL_PRIORITY = 300
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

    def flowmod(self, fm_type='ADD',
                src=None, dst=None, in_port=None, match=None,
                out_port=None,
                vlan_action=None, vlan_id=None,
                priority=OFP_LW_PRIORITY):

        if match is None:
            match = self._ofproto_parser.OFPMatch(
                dl_src=haddr_to_bin(src),
                dl_dst=haddr_to_bin(dst),
                in_port=in_port)
        else:
            match = self._ofproto_parser.OFPMatch(**match)

        if fm_type == 'ADD':

            actions = [self._dp.ofproto_parser.OFPActionOutput(out_port)]

            if vlan_action == 'encap':
                actions.insert(0, self._dp.ofproto_parser.OFPActionVlanVid(
                    vlan_id))

            if vlan_action == 'decap':
                actions.insert(0, self._dp.ofproto_parser.OFPActionStripVlan())

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

            return mod

        if fm_type == 'DEL':

            mod = self._ofproto_parser.OFPFlowMod(
                datapath=self._dp,
                match=match,
                cookie=0,
                command=self._ofproto.OFPFC_DELETE)

            self._dp.send_msg(mod)

            return mod


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

        self.poas = {}
        self.rules = {}
        self.lvnf_info = OrderedDict()
        self.LSwitches = {}
        self.mutex = Lock()
        self.vlan_id = 1000
        self.vlan_dst_map = {}

        wsgi = kwargs['wsgi']
        wsgi.register(IntentController, {'intent_app': self})

    def _get_sws_links(self):

        sws_list = get_switch(self, None)
        sws = [switch.dp.id for switch in sws_list]

        links_list = get_link(self, None)

        links = []
        for link in links_list:
            links.append({'src': link.src.dpid,
                          'dst': link.dst.dpid,
                          'port': link.dst.port_no})

        return sws, links

    def _get_nexthop(self, src_dpid, dst_dpid):

        sws, links = self._get_sws_links()

        _, prev = dijkstra(sws, links, dst_dpid)

        if prev[src_dpid] is None:
            return None, None
        else:
            return prev[src_dpid]  # (next_dpid, current_port)

    def _compile_rule(self, rule):
        """Compile rule."""

        stp_switch = self.LSwitches[rule.stp_dpid]

        # the rule endpoints are on the same switch
        if rule.stp_dpid == rule.ttp_dpid:

            stp_mod = stp_switch.flowmod(match=rule.match,
                                         out_port=rule.ttp_port,
                                         priority=OFP_TUNNEL_PRIORITY)
            rule.flow_mods.append(stp_mod)
            return

        # the rule endpoints are on different switches
        next_dpid, out_port = self._get_nexthop(rule.stp_dpid,
                                                rule.ttp_dpid)

        stp_mod = stp_switch.flowmod(match=rule.match,
                                     out_port=out_port,
                                     vlan_action='encap', vlan_id=self.vlan_id,
                                     priority=OFP_TUNNEL_PRIORITY)

        while next_dpid != rule.ttp_dpid:

            if next_dpid is None:
                self.logger.error('No path found for requested chain')
                return

            switch = self.LSwitches[next_dpid]
            next_dpid, next_port = self._get_nexthop(next_dpid,
                                                     rule.ttp_dpid)
            switch.flowmod(match={'dl_vlan': self.vlan_id},
                           out_port=next_port,
                           priority=OFP_TUNNEL_PRIORITY)

        ttp_switch = self.LSwitches[rule.ttp_dpid]
        ttp_mod = ttp_switch.flowmod(match={'dl_vlan': self.vlan_id},
                                     out_port=rule.ttp_port,
                                     vlan_action='decap',
                                     priority=OFP_TUNNEL_PRIORITY)

        rule.flow_mods.append(stp_mod)
        rule.flow_mods.append(ttp_mod) # only for storing the matching vlan_id

        self.vlan_dst_map[self.vlan_id] = (rule.ttp_dpid, rule.ttp_port)
        self.vlan_id += 1

    def _remove_rule(self, rule):

        stp_switch = self.LSwitches[rule.stp_dpid]
        stp_switch.flowmod(fm_type='DEL',
                           match=rule.match)

        # the rule involved only one switch, no vlans have been used
        if len(rule.flow_mods) > 1:

            vlan_id = rule.flow_mods[1].match['dl_vlan']

            for sw_id in self.LSwitches:
                self.LSwitches[sw_id].flowmod(fm_type='DEL',
                                              match={'dl_vlan': vlan_id})

    def _find_host_dpid(self, mac):

        dpid = None
        dp_host_port = None

        for sw_id in self.LSwitches:

            hosts = get_host(self, sw_id)
            target_host = [host for host in hosts
                           if host.mac == mac.lower()]

            if len(target_host) > 0:

                # assert that Ryu report this host on only one dp and port
                assert dpid is None
                assert dp_host_port is None
                assert len(target_host) == 1
                target_host = target_host[0]
                dpid = sw_id
                dp_host_port = target_host.port.port_no

        return dpid, dp_host_port

    def add_rule(self, rule):

        try:

            self.mutex.acquire()

            self.logger.info('adding rule: %s' % rule.uuid)
            self.logger.info(rule.to_jsondict())

            self._compile_rule(rule)

            self.rules[rule.uuid] = rule

            self.mutex.release()

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    def remove_rule(self, uuid=None):

        try:

            self.mutex.acquire()

            if uuid:
                self.logger.info('removing rule: %s' % uuid)
                rule = self.rules[uuid]
                self._remove_rule(rule)
                del self.rules[uuid]
            else:
                self.logger.info('removing all rules')
                for uuid in list(self.rules):
                    rule = self.rules[uuid]
                    self._remove_rule(rule)
                    del self.rules[uuid]

        except KeyError:
            raise
        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    def update_poa(self, uuid, poa):

        if poa != self.poas[uuid]:
            self.remove_poa(uuid)
            self.add_poa(poa)

    def add_poa(self, poa):

        try:

            self.mutex.acquire()

            self.logger.info('adding POA: %s' % poa.uuid)
            self.logger.info(poa.to_jsondict())

            mac = poa.hwaddr

            # delete all rules and unlearn host
            for switch in self.LSwitches.values():

                switch.delete_host_rules(mac)
                switch.delete_host(mac)

            self.poas[poa.uuid] = poa

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    def remove_poa(self, uuid=None):

        try:

            self.mutex.acquire()

            if uuid:
                self.logger.info('removing POA: %s' % uuid)
                del self.poas[uuid]
            else:
                self.logger.info('removing all POAs')
                for uuid in list(self.poas):
                    del self.poas[uuid]

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        vlan_pkt = pkt.get_protocol(vlan.vlan)

        if vlan_pkt is not None:
            # vlan-tagged vnf traffic is related to rules
            # and has its own circuits
            return

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

            if dpid in self.LSwitches:

                switch = self.LSwitches[dpid]

                if not switch.get_dp().is_active:

                    # switch has restarted
                    self.logger.info('%s (%s) has reconnected'
                                     % (dpid_to_empower(dpid), dpid))

                    del self.LSwitches[dpid]
                    switch = LSwitch(datapath)
                    self.LSwitches[dpid] = switch

            else:
                self.logger.info('%s (%s) has connected' %
                                 (dpid_to_empower(dpid), dpid))

                switch = LSwitch(datapath)
                self.LSwitches[dpid] = switch

            # for both src and dst check whether these are controlled by Empower
            empower_src_list = [rule for rule in self.poas.values()
                                if rule.hwaddr == src]
            assert len(empower_src_list) <= 1
            empower_src = None
            if len(empower_src_list) == 1:
                empower_src = empower_src_list[0]

            empower_dst_list = [rule for rule in self.poas.values()
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
                    switch.flowmod(src=src, dst=dst, in_port=msg.in_port,
                                   out_port=out_port)
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

                _, nexthop_port = self._get_nexthop(switch.get_dp_id(),
                                                    target_dpid)

                if nexthop_port is None:
                    nexthop_port = target_port

                switch.flowmod(src=src, dst=dst, in_port=msg.in_port,
                               out_port=nexthop_port,
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

        dpid_str = dpid_to_empower(msg.datapath.id)

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added dpid=%s, port=%s",
                             dpid_str, port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted dpid=%s, port=%s",
                             dpid_str, port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified dpid=%s, port=%s",
                             dpid_str, port_no)
        else:
            self.logger.info("Illeagal port state dpid=%s, port=%s %s",
                             dpid_str, port_no, reason)
