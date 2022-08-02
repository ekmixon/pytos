#!/opt/tufin/securitysuite/ps/python/bin/python3.4
import os
import unittest
import sys
import xml.etree.ElementTree as ET
from pytos.securechange.xml_objects.securechange_api import Ticket_Info


def fake_request_response(rest_file):
    full_path = os.path.dirname(os.path.abspath(__file__))
    sub_resources_dir = sys._getframe(1).f_locals['self'].__class__.__name__.lower()
    resource_file = os.path.join(
        full_path, "resources", sub_resources_dir, f"{rest_file}.xml"
    )

    with open(resource_file, mode='rb') as f:
        return f.read()


class Test_Secure_Change_XML(unittest.TestCase):
    def test_01_ticket_info(self):
        ticket_info_xml_node = ET.fromstring(fake_request_response("ticket_info").decode())
        ticket_info = Ticket_Info(ticket_info_xml_node)
        self.assertIsInstance(ticket_info, Ticket_Info)
        self.assertEqual(ticket_info.id, 1)


if __name__ == '__main__':
    unittest.main()

