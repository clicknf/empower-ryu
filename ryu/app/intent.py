# Copyright (C) 2018 Giovanni Baggio.
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


from ryu import cfg
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
from ryu.lib.ofctl_v1_0 import to_match, to_actions
from collections import OrderedDict
from ryu.app.wsgi import WSGIApplication
from threading import Lock
import traceback
import json

from ryu.topology.event import EventHostAdd, EventLinkAdd, EventSwitchEnter

from ryu.app.agent_intent import dpid_to_empower
from ryu.app.agent_intent import IntentEncoder
from ryu.app.agent_intent import start_agent

OFP_LW_PRIORITY = 100
OFP_RULE_PRIORITY = 200
OFP_CUSTOM_PRIORITY = 250
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

    def packet_out(self, msg, port):

        if msg.in_port == port:
            out_port = ofproto_v1_0.OFPP_IN_PORT
        else:
            out_port = port

        actions = [self._dp.ofproto_parser.OFPActionOutput(out_port)]
        data = None

        if msg.buffer_id == self._ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = self._dp.ofproto_parser.OFPPacketOut(
            datapath=self._dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)

        self._dp.send_msg(out)

    def add_ofrule(self, match, actions, priority):

        if 'in_port' in match:
            for action in actions:
                if action['type'] != 'OUTPUT':
                    continue
                if action['port'] == match['in_port']:
                    action['port'] = ofproto_v1_0.OFPP_IN_PORT

        mod = self._ofproto_parser.OFPFlowMod(
            datapath=self._dp,
            match=to_match(self._dp, match),
            cookie=0,
            command=self._ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            priority=priority,
            flags=self._ofproto.OFPFF_SEND_FLOW_REM,
            actions=to_actions(self._dp, actions))

        self._dp.send_msg(mod)

    def remove_ofrule(self, match):

        mod = self._ofproto_parser.OFPFlowMod(
            datapath=self._dp,
            match=to_match(self._dp, match),
            cookie=0,
            command=self._ofproto.OFPFC_DELETE)

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

        conf = cfg.CONF
        conf.register_opts([
            cfg.StrOpt('empower_ip',
                       default='127.0.0.1',
                       help=('The Empower Runtime controller ip')),
            cfg.IntOpt('empower_port',
                       default=4444,
                       help=('The Empower Runtime controller port'))])

        self.endpoints = {}
        self.rules = {}
        self.lvnf_info = OrderedDict()
        self.LSwitches = {}
        self.mutex = Lock()
        self._vlan_id = 1000

        self.agent = start_agent(conf.empower_ip, conf.empower_port, 2, self)

    def next_vlan_id(self):

        self._vlan_id += 1
        return self._vlan_id

    def get_switches(self):

        switches = []

        for switch in get_switch(self, None):
            if switch.dp.id in self.LSwitches:
                switches.append(switch)

        return switches

    def get_links(self):

        return list(get_link(self, None).keys())

    def get_hosts(self):

        return get_host(self, None)

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

        stp_dpid = rule.stp_endpoint.dpid
        stp_switch = self.LSwitches[stp_dpid]

        ttp_dpid = rule.ttp_endpoint.dpid
        ttp_endpoint_port = rule.ttp_endpoint.ports[rule.ttp_vport]
        ttp_port = ttp_endpoint_port.port_no

        actions = list(rule.actions)

        if rule.priority is not None:
            priority = OFP_CUSTOM_PRIORITY + rule.priority
        else:
            priority = OFP_TUNNEL_PRIORITY

        # the rule endpoints are on the same switch
        if stp_dpid == ttp_dpid:

            actions.append({'type': 'OUTPUT', 'port': ttp_port})

            stp_switch.add_ofrule(rule.match,
                                  actions,
                                  priority)

            return

        # the rule endpoints are on different switches
        next_dpid, out_port = self._get_nexthop(stp_dpid, ttp_dpid)
        vlan_id = self.next_vlan_id()

        actions.append({'type': 'SET_VLAN_VID', 'vlan_vid': vlan_id})
        actions.append({'type': 'OUTPUT', 'port': out_port})

        stp_switch.add_ofrule(rule.match, actions, priority)

        while next_dpid != ttp_dpid:

            if next_dpid is None:
                self.logger.error('No path found for requested chain')
                return

            switch = self.LSwitches[next_dpid]
            next_dpid, next_port = self._get_nexthop(next_dpid, ttp_dpid)
            out_action = [{'type': 'OUTPUT', 'port': next_port}]
            switch.add_ofrule({'dl_vlan': vlan_id}, out_action, priority)

        out_decap_actions = [{'type': 'STRIP_VLAN'},
                             {'type': 'OUTPUT', 'port': ttp_port}]
        ttp_switch = self.LSwitches[ttp_dpid]
        ttp_switch.add_ofrule({'dl_vlan': vlan_id}, out_decap_actions, priority)

        rule.vlan = vlan_id

    def _remove_rule(self, rule):

        stp_dpid = rule.stp_endpoint.dpid
        stp_switch = self.LSwitches[stp_dpid]
        stp_switch.remove_ofrule(rule.match)

        # the rule involved only one switch, no vlans have been used
        if rule.vlan:

            vlan_id = rule.vlan

            for sw_id in self.LSwitches:
                self.LSwitches[sw_id].remove_ofrule({'dl_vlan': vlan_id})

    def _remove_empower_hosts(self, endpoint):
        # delete all rules and unlearn host

        for switch in self.LSwitches.values():

            for port in endpoint.ports.values():

                for hwaddr in port.dont_learn:

                    switch.delete_host_rules(hwaddr)
                    switch.delete_host(hwaddr)

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
            self.logger.info(json.dumps(rule.to_jsondict(),
                                        cls=IntentEncoder))

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
                if uuid in self.rules:
                    rule = self.rules[uuid]
                    self._remove_rule(rule)
                    del self.rules[uuid]
                else:
                    self.logger.warning('rule uuid %s not found' % uuid)

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

    def update_endpoint(self, endpoint):

        uuid = endpoint.uuid

        if uuid in self.endpoints and endpoint != self.endpoints[uuid]:
            self.remove_endpoint(uuid)

        self._add_endpoint(endpoint)

    def _add_endpoint(self, endpoint):

        try:

            self.mutex.acquire()

            self.logger.info('adding EndPoint: %s' % endpoint.uuid)
            self.logger.info(json.dumps(endpoint.to_jsondict(),
                                        cls=IntentEncoder))

            self._remove_empower_hosts(endpoint)

            self.endpoints[endpoint.uuid] = endpoint

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    def remove_endpoint(self, uuid=None):

        try:

            self.mutex.acquire()

            if uuid:
                self.logger.info('removing EndPoint: %s' % uuid)
                if uuid in self.endpoints:
                    endpoint = self.endpoints[uuid]
                    self._remove_empower_hosts(endpoint)
                    del self.endpoints[uuid]
                else:
                    self.logger.warning('endpoint uuid %s not found' % uuid)
            else:
                self.logger.info('removing all EndPoints')
                for uuid in list(self.endpoints):
                    endpoint = self.endpoints[uuid]
                    self._remove_empower_hosts(endpoint)
                    del self.endpoints[uuid]

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.mutex.release()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg

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
            self._packet_in_empowerhandler(msg, src, dst)
        except Exception:
            traceback.print_exc()
            raise
        finally:
            self.mutex.release()

    def _packet_in_empowerhandler(self, msg, src, dst):

        datapath = msg.datapath
        in_port = msg.in_port
        ofproto = datapath.ofproto

        if datapath.id not in self.LSwitches:
            raise KeyError('Packet in received before datapath announcement')

        switch = self.LSwitches[datapath.id]

        # for both src and dst check whether these are controlled by Empower
        empower_src_list = [endpoint for endpoint in self.endpoints.values()
                            if src in endpoint.hwaddr_to_port]
        assert len(empower_src_list) <= 1
        empower_src = None
        if len(empower_src_list) == 1:
            empower_src = empower_src_list[0]

        empower_dst_list = [endpoint for endpoint in self.endpoints.values()
                            if dst in endpoint.hwaddr_to_port]
        assert len(empower_dst_list) <= 1
        empower_dst = None
        if len(empower_dst_list) == 1:
            empower_dst = empower_dst_list[0]

        # in case both src and dst are unknown to Empower, proceed with
        # regular learning switch
        if empower_src is None and empower_dst is None:

            # learn a mac address to avoid FLOOD next time.
            switch.update_host(src, in_port)

            out_port = switch.get_host_port(dst)

            if out_port is None:
                switch.packet_out(msg, ofproto.OFPP_FLOOD)
                return
            priority = OFP_LW_PRIORITY

        else:

            # either src or dst are Empower controlled,
            target_dpid, target_port = None, None

            if empower_dst is None:
                target_dpid, target_port = self._find_host_dpid(dst)

            if empower_dst is not None:
                endpoint_port = empower_dst.hwaddr_to_port[dst]
                target_dpid = endpoint_port.endpoint.dpid
                target_port = endpoint_port.port_no

            if target_dpid is None:

                switch.packet_out(msg, ofproto.OFPP_FLOOD)
                return

            _, out_port = self._get_nexthop(switch.get_dp_id(),
                                            target_dpid)

            if out_port is None:
                out_port = target_port
            priority = OFP_RULE_PRIORITY

        match = {'dl_src': src,
                 'dl_dst': dst,
                 'in_port': in_port}
        out_action = [{'type': 'OUTPUT', 'port': out_port}]

        switch.add_ofrule(match, out_action, priority)
        switch.packet_out(msg, out_port)



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



    @set_ev_cls(EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):

        #dpid = datapath.id
        datapath = ev.switch.dp
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
            switch.remove_ofrule({})
            self.LSwitches[dpid] = switch


        self.agent.send_of_network_item(ev.switch)

    @set_ev_cls(EventLinkAdd)
    def _event_link_add_handler(self, ev):
        self.agent.send_of_network_item(ev.link)

    @set_ev_cls(EventHostAdd)
    def _event_host_add_handler(self, ev):
        self.agent.send_of_network_item(ev.host)
