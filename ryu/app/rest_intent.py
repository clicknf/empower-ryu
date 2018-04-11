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

import json

from uuid import UUID
from uuid import uuid4
from webob import Response

from ryu.app.wsgi import ControllerBase, route
from ryu.ofproto.ofproto_v1_0_parser import OFPMatch
from ryu.ofproto.ofproto_v1_0_parser import OFPFlowMod
from ryu.lib import dpid as dpid_lib


def empower_to_dpid(mac):
    """Convert from empower format to dpid."""

    if not mac:
        return None

    return dpid_lib.str_to_dpid('{:<16}'.format(mac.replace(':', '')))


def dpid_to_empower(dpid):
    """Convert from dpid format to empower."""

    if not dpid:
        return None

    tmp = dpid_lib.dpid_to_str(dpid)
    tmp = tmp[2:]

    return ':'.join(tmp[i:i + 2] for i in range(0, len(tmp), 2))


class IntentRule(object):

    def __init__(self, uuid, rule, endpoints):

        self.uuid = uuid

        ttp_uuid = UUID(rule['ttp_uuid'])
        self.ttp_endpoint = endpoints[ttp_uuid]
        self.ttp_vport = int(rule['ttp_vport'])

        stp_uuid = UUID(rule['stp_uuid'])
        self.stp_endpoint = endpoints[stp_uuid]
        self.stp_vport = int(rule['stp_vport'])

        self.match = rule['match']

        if rule['match'] == {}:
            ovs_port = self.stp_endpoint.ports[self.stp_vport]
            self.match = {'in_port': ovs_port.port_no}

        self.flow_mods = []

    def to_jsondict(self):
        """Return JSON representation of this object."""

        out = {'ttp_endpoint': self.ttp_endpoint,
               'ttp_vport': self.ttp_vport,
               'uuid': self.uuid,
               'stp_endpoint': self.stp_endpoint,
               'stp_vport': self.stp_vport,
               'match': self.match,
               'flow_mods': self.flow_mods}

        return {'IntentRule': out}

    def __eq__(self, other):

        return self.ttp_endpoint == other.ttp_endpoint and \
               self.ttp_vport == other.ttp_vport and \
               self.match == other.match


class IntentEndPoint(object):

    class Port:

        def __init__(self, port):
            self.hwaddr = port['hwaddr'].upper()
            self.dpid = empower_to_dpid(port['dpid'])
            self.port_no = int(port['port_no'])
            self.learn_host = bool(port['learn_host'])

        def to_jsondict(self):
            """Return JSON representation of this object."""

            out = {'hwaddr': self.hwaddr,
                   'dpid': dpid_to_empower(self.dpid),
                   'port_no': self.port_no,
                   'learn_host': self.learn_host}

            return {'IntentEndPoint.Port': out}

    def __init__(self, uuid, endpoint):

        self.uuid = uuid
        self.ports = {}
        self.hwaddr_to_port = {}

        for v_port_id, v_port in endpoint['ports'].items():

            port = self.Port(v_port)
            self.ports[int(v_port_id)] = port

            if port.learn_host:
                self.hwaddr_to_port[port.hwaddr] = port

    def to_jsondict(self):
        """Return JSON representation of this object."""

        out = {'ports': self.ports,
               'uuid': self.uuid}

        return {'IntentEndPoint': out}

    def __eq__(self, other):

        return self.ports == other.ports


class IterEncoder(json.JSONEncoder):
    """Encode iterable objects as lists."""

    def default(self, obj):
        try:
            return list(obj)
        except TypeError:
            return super(IterEncoder, self).default(obj)


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


class IntentController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(IntentController, self).__init__(req, link, data, **config)
        self.intent_app = data['intent_app']

    # ENDPOINTS
    @route('intent', '/intent/eps', methods=['GET'])
    def get_endpoints(self, req, **kwargs):

        try:
            body = \
                json.dumps(self.intent_app.endpoints.values(), cls=IntentEncoder)
            return Response(content_type='application/json',
                            body=body,
                            charset='utf-8')
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/eps/{uuid}', methods=['GET'])
    def get_endpoint(self, req, **kwargs):

        try:
            uuid = UUID(kwargs['uuid'])
            body = json.dumps(self.intent_app.endpoints[uuid], cls=IntentEncoder)
            return Response(content_type='application/json',
                            body=body,
                            charset='utf-8')
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/eps', methods=['DELETE'])
    def delete_endpoints(self, req, **kwargs):

        try:
            self.intent_app.remove_endpoint()
            return Response(status=204)
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/eps/{uuid}', methods=['DELETE'])
    def delete_endpoint(self, req, **kwargs):

        try:
            uuid = UUID(kwargs['uuid'])
            self.intent_app.remove_endpoint(uuid)
            return Response(status=204)
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/eps/{uuid}', methods=['PUT'])
    def update_endpoint(self, req, **kwargs):

        try:

            body = json.loads(str(req.body, 'utf-8'))
            uuid = UUID(kwargs['uuid'])

            if uuid not in self.intent_app.endpoints:
                endpoint = IntentEndPoint(uuid, body)
                self.intent_app.add_endpoint(endpoint)
                return Response(status=201)

            endpoint = IntentEndPoint(uuid, body)
            self.intent_app.update_endpoint(uuid, endpoint)
            return Response(status=204)

        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/eps', methods=['POST'])
    def add_endpoint(self, req, **kwargs):

        try:

            body = json.loads(str(req.body, 'utf-8'))
            endpoint = IntentEndPoint(uuid4(), body)

            self.intent_app.add_endpoint(endpoint)
            headers = {'Location': '/intent/eps/%s' % endpoint.uuid}

            return Response(status=201, headers=headers)

        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    # RULES
    @route('intent', '/intent/rules', methods=['POST'])
    def add_rule(self, req, **kwargs):

        try:

            body = json.loads(str(req.body, 'utf-8'))
            rule = IntentRule(uuid4(), body, self.intent_app.endpoints)

            self.intent_app.add_rule(rule)
            headers = {'Location': '/intent/rule/%s' % rule.uuid}

            return Response(status=201, headers=headers)

        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules/{uuid}', methods=['DELETE'])
    def delete_rule(self, req, **kwargs):

        try:
            uuid = UUID(kwargs['uuid'])
            self.intent_app.remove_rule(uuid)
            return Response(status=204)
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules', methods=['DELETE'])
    def delete_rules(self, req, **kwargs):

        try:
            self.intent_app.remove_rule()
            return Response(status=204)
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules', methods=['GET'])
    def get_rules(self, req, **kwargs):

        try:
            body = \
                json.dumps(self.intent_app.rules.values(), cls=IntentEncoder)
            return Response(content_type='application/json',
                            body=body,
                            charset='utf-8')
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules/{uuid}', methods=['GET'])
    def get_rule(self, req, **kwargs):

        try:
            uuid = UUID(kwargs['uuid'])
            body = json.dumps(self.intent_app.rules[uuid], cls=IntentEncoder)
            return Response(content_type='application/json',
                            body=body,
                            charset='utf-8')
        except KeyError:
            return Response(status=404)
        except ValueError:
            return Response(status=400)
