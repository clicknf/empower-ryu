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

from webob import Response
from uuid import UUID
from uuid import uuid4

from ryu.app.wsgi import ControllerBase, route
from ryu.ofproto.ofproto_v1_0_parser import OFPMatch
from ryu.ofproto.ofproto_v1_0_parser import OFPFlowMod
from ryu.lib import dpid as dpid_lib


VALID = [set(['version', 'ttp_dpid', 'ttp_port', 'match']),
         set(['version', 'stp_dpid', 'stp_dpid', 'match',
              'ttp_dpid', 'ttp_port'])]


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

    def __init__(self, uuid, rule):

        self.uuid = uuid
        self.ttp_dpid = empower_to_dpid(rule['ttp_dpid'])
        self.ttp_port = int(rule['ttp_port'])
        self.match = rule['match']
        self.stp_dpid = None
        self.stp_port = None
        self.flow_mods = []

        if 'stp_dpid' in rule:
            self.stp_dpid = empower_to_dpid(rule['stp_dpid'])
            self.stp_port = int(rule['stp_port'])

    def to_jsondict(self):
        """Return JSON representation of this object."""

        out = {'ttp_dpid': dpid_to_empower(self.ttp_dpid),
               'ttp_port': self.ttp_port,
               'uuid': self.uuid,
               'stp_dpid': dpid_to_empower(self.stp_dpid),
               'stp_port': self.stp_port,
               'match': self.match,
               'flow_mods': self.flow_mods}

        return {'IntentRule': out}


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
            ret = obj.to_jsondict()
            return ret['OFPMatch']
        if isinstance(obj, OFPFlowMod):
            ret = obj.to_jsondict()
            return ret['OFPFlowMod']
        if isinstance(obj, IntentRule):
            ret = obj.to_jsondict()
            return ret['IntentRule']
        return super(IntentEncoder, self).default(obj)


class IntentController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(IntentController, self).__init__(req, link, data, **config)
        self.intent_app = data['intent_app']

    @route('intent', '/intent/rules', methods=['GET'])
    def get_rules(self, req, **kwargs):

        body = json.dumps(self.intent_app.rules.values(), cls=IntentEncoder)
        return Response(content_type='application/json', body=body)

    @route('intent', '/intent/rules/{uuid}', methods=['GET'])
    def get_rule(self, req, **kwargs):

        try:

            uuid = UUID(kwargs['uuid'])
            body = json.dumps(self.intent_app.rules[uuid],
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
            return Response(status=204)

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

    @route('intent', '/intent/rules/{uuid}', methods=['PUT'])
    def update_rule(self, req, **kwargs):

        try:

            body = json.loads(req.body)
            keys = set(body.keys())

            if keys not in VALID:
                return Response(status=400)

            uuid = UUID(kwargs['uuid'])

            if uuid not in self.intent_app.rules:
                raise KeyError("Unable to find %s", uuid)

            rule = IntentRule(uuid, body)
            self.intent_app.update_rule(uuid, rule)

            return Response(status=204)

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

            rule = IntentRule(uuid4(), body)
            self.intent_app.add_rule(rule)
            headers = {'Location': '/intent/rules/%s' % rule.uuid}

            return Response(status=201, headers=headers)

        except KeyError:
            return Response(status=404)

        except ValueError:
            return Response(status=400)
