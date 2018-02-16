import requests
import unittest
import xmlrunner
import logging
import time
import sys

root = 'http://root:root@127.0.0.1:8888/api/v1'
foo = 'http://foo:foo@127.0.0.1:8888/api/v1'


class ClassTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClassTest, self).__init__(*args, **kwargs)

        self.LOG = logging.getLogger()
        self.LOG.setLevel(logging.DEBUG)

        self.LVAP = '00:24:D7:7B:B0:7C'

        self.VNF1_mac = '66:C3:CE:D9:05:51'

        self.LVNF1_id = '20c7ecf7-be9e-4643-8f98-8ac582b4bc03'
        self.LVNF2_id = '20c7ecf7-be9e-4643-8f98-8acda49023ba'
        self.LVNF3_id = '20c7ecf7-be9e-4643-8f98-8ac3a4602aca'
        self.LVNF4_id = '20c7ecf7-be9e-4643-8f98-8ac3a4602949'

        self.tenant_id = 'b1a913be-0b20-4f3a-8479-66724dad8fbb'

    def initial_check(self):

        logging.info('Checking pre-conditions...')

        response = requests.get(foo + '/lvaps/')
        self.assertEqual(response.status_code, 200)

        url = foo + '/tenants/%s/lvaps/' % self.tenant_id
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)

        response = requests.get(foo + '/lvaps/' + self.LVAP)
        self.assertEqual(response.status_code, 200)

        url = foo + '/tenants/%s/lvaps/%s' % (self.tenant_id, self.LVAP)
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)

        time.sleep(5)

    def cleanup(self):

        self.LOG.info('DELETING RESOURCES...')

        response = requests.delete(
            foo + '/tenants/%s/lvaps/%s/ports/0/next/dl_dst=%s'
            % (self.tenant_id, self.LVAP, self.VNF1_mac))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        response = requests.get(foo + '/tenants/%s/lvnfs/%s/ports/0'
                                % (self.tenant_id, self.LVNF1_id))
        self.assertIn(response.status_code, [200, 404])

        if response.status_code == 200:
            vnf1_old_ovs_port = response.json()['poas'][0]['port_id']

            response = requests.delete(
                foo + '/tenants/%s/lvnfs/%s/ports/0/next/'
                      'in_port=%s,dl_type=%s,nw_proto=%s'
                % (self.tenant_id,
                   self.LVNF1_id,
                   vnf1_old_ovs_port,
                   '0x0800',
                   1))
            self.assertIn(response.status_code, [204, 404])

            time.sleep(5)

            response = requests.delete(
                foo + '/tenants/%s/lvnfs/%s/ports/0/next/'
                      'in_port=%s,dl_type=%s,nw_proto=%s'
                % (self.tenant_id,
                   self.LVNF1_id,
                   vnf1_old_ovs_port,
                   '0x0800',
                   6))
            self.assertIn(response.status_code, [204, 404])

            time.sleep(5)

        response = requests.delete(foo + '/tenants/%s/lvnfs/%s/ports/0/next/'
                                   % (self.tenant_id, self.LVNF2_id))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        response = requests.delete(foo + '/tenants/%s/lvnfs/%s/ports/0/next/'
                                   % (self.tenant_id, self.LVNF3_id))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        self.LOG.info('Removing VNF 1...')

        response = requests.delete(foo + '/tenants/%s/lvnfs/%s'
                                   % (self.tenant_id, self.LVNF1_id))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        self.LOG.info('Removing VNF 2...')

        response = requests.delete(foo + '/tenants/%s/lvnfs/%s'
                                   % (self.tenant_id, self.LVNF2_id))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        self.LOG.info('Removing VNF 3...')

        response = requests.delete(foo + '/tenants/%s/lvnfs/%s'
                                   % (self.tenant_id, self.LVNF3_id))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        self.LOG.info('Removing VNF 4...')

        response = requests.delete(foo + '/tenants/%s/lvnfs/%s'
                                   % (self.tenant_id, self.LVNF4_id))
        self.assertIn(response.status_code, [204, 404])

        time.sleep(5)

        self.LOG.info('RESOURCES DELETION PROCESS COMPLETED...')

    def create_VNF1(self):

        self.LOG.info('Creating VNF1...')

        data = {
                "version": "1.0",
                "image": {
                    "nb_ports": 1,
                    "vnf": "in_0 -> Classifier(12/bbbb) "
                           "-> Strip(14) -> dupe::ScyllaWifiDupeFilter() "
                           "-> WifiDecap() -> out_0",
                    "handlers": [
                        [
                            "dupes_table",
                            "dupe.dupes_table"
                        ]
                    ],
                    "state_handlers": [
                        "dupes_table"
                    ]
                },
                "addr": "00:00:24:D1:DE:E9"
            }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s'
                                 % (self.tenant_id, self.LVNF1_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Setup pollers VNF1...')

        data = {
                "version": "1.0",
                "every": 2000,
                "lvnf": self.LVNF1_id
            }

        response = requests.post(foo + '/tenants/%s/lvnf_stats'
                                 % self.tenant_id, json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        data = {
                "version": "1.0",
                "every": 2000,
                "lvnf": self.LVNF1_id,
                "handler": "dupes_table"
            }

        response = requests.post(foo + '/tenants/%s/lvnf_get'
                                 % self.tenant_id, json=data)

        self.assertEqual(response.status_code, 201)

    def create_VNF2(self):

        self.LOG.info('Creating VNF2...')

        data = {
                "version": "1.0",
                "image": {
                    "nb_ports": 1,
                    "vnf": "in_0 -> CheckICMPHeader -> out_0",
                    "handlers": [
                        [
                            "dupes_table",
                            "dupe.dupes_table"
                        ]
                    ],
                    "state_handlers": [
                        "dupes_table"
                    ]
                },
                "addr": "00:00:24:d1:61:ed"
            }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s'
                                 % (self.tenant_id, self.LVNF2_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Setup pollers VNF2...')

        data = {
                "version": "1.0",
                "every": 2000,
                "lvnf": self.LVNF2_id
            }

        response = requests.post(foo + '/tenants/%s/lvnf_stats'
                                 % self.tenant_id, json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

    def create_VNF3(self):

        self.LOG.info('Creating VNF3...')

        data = {
                "version": "1.0",
                "image": {
                    "nb_ports": 1,
                    "vnf": "in_0 -> CheckTCPHeader -> out_0",
                    "handlers": [
                        [
                            "dupes_table",
                            "dupe.dupes_table"
                        ]
                    ],
                    "state_handlers": [
                        "dupes_table"
                    ]
                },
                "addr": "00:00:24:d1:de:e5"
            }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s'
                                 % (self.tenant_id, self.LVNF3_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Setup pollers VNF3...')

        data = {
                "version": "1.0",
                "every": 2000,
                "lvnf": self.LVNF3_id
            }

        response = requests.post(foo + '/tenants/%s/lvnf_stats'
                                 % self.tenant_id, json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

    def create_VNF4(self):

        self.LOG.info('Creating VNF4...')

        data = {
                "version": "1.0",
                "image": {
                    "nb_ports": 1,
                    "vnf": "in_0 -> out_0",
                    "handlers": [
                        [
                            "dupes_table",
                            "dupe.dupes_table"
                        ]
                    ],
                    "state_handlers": [
                        "dupes_table"
                    ]
                },
                "addr": "00:00:24:D1:de:e9"
        }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s'
                                 % (self.tenant_id, self.LVNF4_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Setup pollers VNF4...')

        data = {
                "version": "1.0",
                "every": 2000,
                "lvnf": self.LVNF4_id
            }

        response = requests.post(foo + '/tenants/%s/lvnf_stats'
                                 % self.tenant_id, json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

    def test(self):

        self.initial_check()

        # comment out this block for skipping VNF deletion / creation steps
        self.cleanup()
        self.create_VNF1()
        self.create_VNF2()
        self.create_VNF3()
        self.create_VNF4()

        self.LOG.info('Setting multiple uplinks (no encap)...')

        data = {
                "version": "1.0",
                "encap": "00:00:00:00:00:00",
                "blocks": [
                    {
                        "wtp": "00:0D:B9:2F:56:64",
                        "channel": "1",
                        "band": "1",
                        "hwaddr": "04:F0:21:09:F9:98"
                    },
                    {
                        "wtp": "00:0D:B9:2F:55:CC",
                        "channel": "1",
                        "band": "1",
                        "hwaddr": "04:F0:21:09:F9:8F"
                    },
                    {
                        "wtp": "00:0D:B9:2F:56:5C",
                        "channel": "1",
                        "band": "1",
                        "hwaddr": "04:F0:21:09:F9:9F"
                    }
                ]
            }

        response = requests.put(foo + '/tenants/%s/lvaps/%s'
                                % (self.tenant_id, self.LVAP), json=data)
        self.assertEqual(response.status_code, 204)

        time.sleep(5)

        self.LOG.info('Encapsulating traffic...')

        data = {
                "version": "1.0",
                "encap": self.VNF1_mac
            }

        response = requests.put(foo + '/tenants/%s/lvaps/%s'
                                % (self.tenant_id, self.LVAP), json=data)
        self.assertEqual(response.status_code, 204)

        time.sleep(5)

        self.LOG.info('Chaining LVAP to VNF1...')

        data = {
                "version": "1.0",
                "match": "dl_dst=%s" % self.VNF1_mac,
                "next": {
                    "lvnf_id": self.LVNF1_id,
                    "port_id": 0
                }
            }

        response = requests.post(foo + '/tenants/%s/lvaps/%s/ports/0/next'
                                 % (self.tenant_id, self.LVAP), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        response = requests.get(foo + '/tenants/%s/lvnfs/%s/ports/0'
                                % (self.tenant_id, self.LVNF1_id))
        self.assertEqual(response.status_code, 200)
        vnf1_ovs_port = response.json()['poas'][0]['port_id']

        self.LOG.info('Chaining VNF1 to VNF2...')

        data = {
                "version": "1.0",
                "match": "in_port=%s,dl_type=%s,nw_proto=%s"
                         % (vnf1_ovs_port, '0x0800', 1),
                "next": {
                    "lvnf_id": self.LVNF2_id,
                    "port_id": 0
                    }
        }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s/ports/0/next'
                                 % (self.tenant_id, self.LVNF1_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Chaining VNF1 to VNF3...')

        data = {
                "version": "1.0",
                "match": "in_port=%s,dl_type=%s,nw_proto=%s"
                         % (vnf1_ovs_port, '0x0800', 6),
                "next": {
                    "lvnf_id": self.LVNF3_id,
                    "port_id": 0
                    }
        }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s/ports/0/next'
                                 % (self.tenant_id, self.LVNF1_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Chaining VNF2 to VNF4...')

        data = {
                "version": "1.0",
                "match": "",
                "next": {
                    "lvnf_id": self.LVNF4_id,
                    "port_id": 0
                }
        }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s/ports/0/next'
                                 % (self.tenant_id, self.LVNF2_id), json=data)
        self.assertEqual(response.status_code, 201)

        time.sleep(5)

        self.LOG.info('Chaining VNF3 to VNF4...')

        data = {
                "version": "1.0",
                "match": "",
                "next": {
                    "lvnf_id": self.LVNF4_id,
                    "port_id": 0
                }
            }

        response = requests.post(foo + '/tenants/%s/lvnfs/%s/ports/0/next'
                                 % (self.tenant_id, self.LVNF3_id), json=data)
        self.assertEqual(response.status_code, 201)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout)
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
