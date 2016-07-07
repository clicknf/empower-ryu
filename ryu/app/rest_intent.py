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

import uuid
import json

from webob import Response

from ryu.app.wsgi import ControllerBase, route
from ryu.ofproto.ofproto_v1_0_parser import OFPMatch
from ryu.lib import dpid as dpid_lib


VALID = [set(['version', 'src_dpid', 'src_port', 'hwaddr']),
         set(['version', 'src_dpid', 'src_port', 'hwaddr', 'match',
              'dst_dpid', 'dst_port']),
         set(['version', 'src_dpid', 'src_port', 'match',
              'dst_dpid', 'dst_port'])]


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

    def __init__(self, rule, rule_id=None):

        if rule_id:
            self.uuid = rule_id
        else:
            self.uuid = uuid.uuid4()

        self.src_dpid = empower_to_dpid(rule['src_dpid'])
        self.src_port = int(rule['src_port'])
        self.hwaddr = None
        self.dst_dpid = None
        self.dst_port = None
        self.match = None
        self.flow_mods = []

        if 'hwaddr' in rule:

            self.hwaddr = rule['hwaddr']

        if 'dst_dpid' in rule:

            self.dst_dpid = empower_to_dpid(rule['dst_dpid'])
            self.dst_port = int(rule['dst_port'])
            self.match = OFPMatch(**rule['match'])

    def to_jsondict(self):
        """Return JSON representation of this object."""

        out = {'hwaddr': self.hwaddr,
               'src_dpid': dpid_to_empower(self.src_dpid),
               'src_port': self.src_port,
               'uuid': self.uuid,
               'dst_dpid': dpid_to_empower(self.dst_dpid),
               'dst_port': self.dst_port,
               'match': self.match}

        return out


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
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if isinstance(obj, OFPMatch):
            return [obj.to_jsondict()]
        if isinstance(obj, IntentRule):
            return [obj.to_jsondict()]
        return super(IntentEncoder, self).default(obj)


class IntentController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(IntentController, self).__init__(req, link, data, **config)
        self.intent_app = data['intent_app']

    @route('intent', '/intent/hwaddrs', methods=['GET'])
    def get_hwaddrs(self, req, **kwargs):

        body = json.dumps(self.intent_app.hwaddrs, cls=IntentEncoder)
        return Response(content_type='application/json', body=body)

    @route('intent', '/intent/vnf_ports', methods=['GET'])
    def get_vnf_ports(self, req, **kwargs):

        body = json.dumps(self.intent_app.vnf_ports, cls=IntentEncoder)
        return Response(content_type='application/json', body=body)

    @route('intent', '/intent/rules', methods=['GET'])
    def get_rules(self, req, **kwargs):

        body = json.dumps(self.intent_app.rules.values(), cls=IntentEncoder)
        return Response(content_type='application/json', body=body)

    @route('intent', '/intent/rules/{uuid}', methods=['GET'])
    def get_rule(self, req, **kwargs):

        try:

            rule_id = uuid.UUID(kwargs['uuid'])
            body = json.dumps(self.intent_app.rules[rule_id],
                              cls=IntentEncoder)
            return Response(content_type='application/json', body=body)

        except KeyError:
            return Response(status=404)

        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules', methods=['DELETE'])
    def delete_rules(self, req, **kwargs):

        try:

            self.intent_app.remove_rule(None)
            return Response(status=202)

        except KeyError:
            return Response(status=404)

        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules/{uuid}', methods=['DELETE'])
    def delete_rule(self, req, **kwargs):

        try:

            rule = uuid.UUID(kwargs['uuid'])
            self.intent_app.remove_rule(rule)
            return Response(status=202)

        except KeyError:
            return Response(status=404)

        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules', methods=['POST'])
    def add_rule(self, req, **kwargs):

        try:

            body = json.loads(req.body)
            keys = set(body.keys())

            if keys not in VALID:
                return Response(status=400)

            rule = self.intent_app.add_rule(body)
            headers = {'Location': '/intent/rules/%s' % rule}

            return Response(status=201, headers=headers)

        except KeyError:
            return Response(status=404)

        except ValueError:
            return Response(status=400)

    @route('intent', '/intent/rules/{uuid}', methods=['POST'])
    def add_rule_by_uuid(self, req, **kwargs):

        try:

            rule_id = uuid.UUID(kwargs['uuid'])

            body = json.loads(req.body)
            keys = set(body.keys())

            if keys not in VALID:
                return Response(status=400)

            if rule_id in self.intent_app.rules:
                return Response(status=409)

            rule = self.intent_app.add_rule(body, rule_id)
            headers = {'Location': '/intent/rules/%s' % rule}

            return Response(status=201, headers=headers)

        except KeyError:
            return Response(status=404)

        except ValueError:
            return Response(status=400)
