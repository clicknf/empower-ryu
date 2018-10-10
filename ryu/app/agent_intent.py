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


import sys
import json
import websocket
import time
import logging

from threading import Thread

from uuid import UUID

import types
from ryu.lib import dpid as dpid_lib
from ryu.topology.switches import Switch, Link, Host

from ryu.ofproto.ofproto_v1_0_parser import OFPMatch
from ryu.ofproto.ofproto_v1_0_parser import OFPFlowMod


PT_VERSION = 0


# ibn to ctrl
PT_HELLO = "hello"
PT_CLEANUP = "cleanup"
PT_NEW_DATAPATH = "new_datapath"
PT_NEW_LINK= "new_link"
PT_NEW_HOST = "new_host"


class IterEncoder(json.JSONEncoder):
    """Encode iterable objects as lists."""

    def default(self, obj):
        try:
            return list(obj)
        except TypeError:
            return super().default(obj)


class EmpowerEncoder(IterEncoder):
    """Handle the representation of the EmPOWER datatypes in JSON format."""

    def default(self, obj):

        if isinstance(obj, types.FunctionType) or \
           isinstance(obj, types.MethodType):
            return obj.__name__

        if isinstance(obj, UUID):
            return str(obj)

        if hasattr(obj, 'to_dict'):

            obj_dict = obj.to_dict()
            return obj_dict

        return super().default(obj)


class IntentEncoder(IterEncoder):
    """Handle the representation of the EmPOWER datatypes in JSON format."""

    def default(self, obj):
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, OFPMatch):
            ret = obj.to_jsondict()
            return ret['OFPMatch']
        if isinstance(obj, OFPFlowMod):
            ret = obj.to_jsondict()
            return ret['OFPFlowMod']
        if isinstance(obj, IntentRule):
            ret = obj.to_jsondict()
            return ret['IntentRule']
        if isinstance(obj, IntentEndPoint):
            ret = obj.to_jsondict()
            return ret['IntentEndPoint']
        if isinstance(obj, IntentEndPoint.Port):
            ret = obj.to_jsondict()
            return ret['IntentEndPoint.Port']
        return super(IntentEncoder, self).default(obj)


def empower_to_dpid(dpid):
    """Convert from empower format to dpid."""

    if not dpid:
        return None

    return dpid_lib.str_to_dpid(dpid.replace(':', ''))


def dpid_to_empower(dpid):
    """Convert from dpid format to empower."""

    empower_dpid = None

    if isinstance(dpid, int):
        empower_dpid = dpid_lib.dpid_to_str(dpid)

    elif isinstance(dpid, str):
        empower_dpid = dpid

    if empower_dpid is None:
        return

    return ':'.join(empower_dpid[i:i + 2].upper()
                    for i in range(0, len(empower_dpid), 2))


class IntentRule(object):

    def __init__(self, rule, endpoints):

        self.uuid = UUID(rule['uuid'])

        ttp_uuid = UUID(rule['ttp_uuid'])
        self.ttp_endpoint = endpoints[ttp_uuid]
        self.ttp_vport = int(rule['ttp_vport'])

        stp_uuid = UUID(rule['stp_uuid'])
        self.stp_endpoint = endpoints[stp_uuid]
        self.stp_vport = int(rule['stp_vport'])

        self.match = rule['match']

        ovs_port = self.stp_endpoint.ports[self.stp_vport]
        self.match['in_port'] = ovs_port.port_no

        self.actions = rule.get('actions', [])
        self.priority = rule.get('priority', None)

        self.vlan = None

    def to_jsondict(self):
        """Return JSON representation of this object."""

        out = {'ttp_endpoint': self.ttp_endpoint,
               'ttp_vport': self.ttp_vport,
               'uuid': self.uuid,
               'stp_endpoint': self.stp_endpoint,
               'stp_vport': self.stp_vport,
               'match': self.match,
               'actions': self.actions,
               'priority': self.priority,
               'vlan': self.vlan}

        return {'IntentRule': out}

    def __eq__(self, other):

        return self.ttp_endpoint == other.ttp_endpoint and \
               self.ttp_vport == other.ttp_vport and \
               self.match == other.match


class IntentEndPoint(object):

    class Port:

        def __init__(self, endpoint, port):
            self.endpoint = endpoint
            self.port_no = int(port['port_no'])
            self.dont_learn = port['properties']['dont_learn']

        def to_jsondict(self):
            """Return JSON representation of this object."""

            out = {'port_no': self.port_no,
                   'dont_learn': self.dont_learn}

            return {'IntentEndPoint.Port': out}

    def __init__(self, endpoint):

        self.uuid = UUID(endpoint['uuid'])
        self.dpid = empower_to_dpid(endpoint['dpid'])
        self.ports = {}
        self.hwaddr_to_port = {}

        for v_port_id, v_port in endpoint['ports'].items():

            port = self.Port(self, v_port)
            self.ports[int(v_port_id)] = port

            for hwaddr in port.dont_learn:
                self.hwaddr_to_port[hwaddr.upper()] = port

    def to_jsondict(self):
        """Return JSON representation of this object."""

        out = {'uuid': self.uuid,
               'dpid': '%s (%s)' % (dpid_to_empower(self.dpid), self.dpid),
               'ports': self.ports}

        return {'IntentEndPoint': out}

    def __eq__(self, other):

        return self.ports == other.ports


def on_open(websock):
    """ Called when the web-socket is opened. """

    logging.info("Socket %s opened...", websock.url)
    websock.connected = True

    websock.send_hello()

    if websock.first_connection:
        websock.first_connection = False

    websock.send_status()

    def periodic_hello(websock):
        """Start hello messages."""

        if websock.sock and websock.sock.connected:
            time.sleep(websock.every)
            websock.send_hello()
            hello_thread = Thread(target=periodic_hello, args=(websock,))
            hello_thread.start()

    hello_thread = Thread(target=periodic_hello, args=(websock,))
    hello_thread.start()


def on_close(websock):
    """ Called when the web-socket is closed. """

    logging.info("Socket %s closed...", websock.url)
    websock.connected = False


def on_message(websock, message):
    """ Called on receiving a new message. """

    try:
        msg = json.loads(message)
        websock.handle_message(msg)
    except ValueError as ex:
        logging.info("Invalid input: %s", ex)
        logging.info(message)


class EmpowerAgent(websocket.WebSocketApp):

    def __init__(self, url, every, intent):

        super().__init__(url)

        self.__seq = 0
        self.every = every

        self.first_connection = True
        self.connected = False
        self.intent = intent
        self.on_open = None
        self.on_close = None
        self.on_message = None

    @property
    def seq(self):
        """Return the next sequence number."""

        self.__seq += 1
        return self.__seq

    def handle_message(self, msg):
        """ Handle incoming message (as a Python dict). """

        handler_name = "_handle_%s" % msg['type']

        if not hasattr(self, handler_name):
            logging.info("Unknown message type: %s", msg['type'])
            return

        handler = getattr(self, handler_name)
        handler(msg)

    def _handle_update_endpoint(self, msg):

        self.intent.update_endpoint(IntentEndPoint(msg))

    def _handle_remove_endpoint(self, msg):

        self.intent.remove_endpoint(UUID(msg['uuid']))

    def _handle_add_rule(self, msg):

        self.intent.add_rule(IntentRule(msg, self.intent.endpoints))

    def _handle_remove_rule(self, msg):

        self.intent.remove_rule(UUID(msg['uuid']))

    def send_message(self, message_type, message):
        """Add fixed header fields and send message. """

        message['version'] = PT_VERSION
        message['type'] = message_type
        message['seq'] = self.seq
        message['every'] = self.every

        msg = json.dumps(message, cls=EmpowerEncoder)

        if self.connected:

            logging.info("Sending %s seq %u", message['type'], message['seq'])
            self.send(msg)

    def send_hello(self):
        """ Send HELLO message. """

        hello = {}
        self.send_message(PT_HELLO, hello)

    def send_status(self):

        of_items = self.intent.get_switches() \
                   + self.intent.get_links() \
                   + self.intent.get_hosts()

        for of_item in of_items:
            self.send_of_network_item(of_item)

    def send_of_network_item(self, of_item):

        item_type = None
        out = of_item.to_dict()

        if isinstance(of_item, Switch):
            item_type = PT_NEW_DATAPATH
            out['ip_addr'] = of_item.dp.address[0]
            out['dpid'] = dpid_to_empower(out['dpid'])

            for port in out['ports']:
                port['port_no'] = int(port['port_no'], 16)
                port['dpid'] = dpid_to_empower(port['dpid'])

        if isinstance(of_item, Link):
            item_type = PT_NEW_LINK
            out['src']['port_no'] = int(out['src']['port_no'], 16)
            out['dst']['port_no'] = int(out['dst']['port_no'], 16)
            out['src']['dpid'] = dpid_to_empower(out['src']['dpid'])
            out['dst']['dpid'] = dpid_to_empower(out['dst']['dpid'])

        if isinstance(of_item, Host):
            item_type = PT_NEW_HOST
            out['port']['dpid'] = dpid_to_empower(out['port']['dpid'])
            out['port']['port_no'] = int(out['port']['port_no'], 16)

        self.send_message(item_type, out)


def _agent_worker(agent):

    while True:
        try:
            logging.info("Trying to connect to controller %s", agent.url)
            agent.run_forever()
            logging.info("Unable to connect, trying again in %us", agent.every)
            time.sleep(agent.every)
        except KeyboardInterrupt:
            agent.shutdown()
            sys.exit()


def start_agent(ip, port, every, intent):

    agent = EmpowerAgent(url="ws://%s:%u/" % (ip, port),
                         every=every,
                         intent=intent)
    agent.on_open = on_open
    agent.on_close = on_close
    agent.on_message = on_message

    agent_thread = Thread(target=_agent_worker, args=(agent,))
    agent_thread.daemon = True
    agent_thread.start()

    return agent
