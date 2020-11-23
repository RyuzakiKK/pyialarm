import logging

import re
import socket
from collections import OrderedDict

import dicttoxml
import xmltodict

log = logging.getLogger(__name__)


class IAlarm(object):
    """
    Interface the iAlarm security systems.
    """

    ARMED_AWAY = 0
    DISARMED = 1
    ARMED_STAY = 2
    CANCEL = 3
    TRIGGERED = 4

    ZONE_NOT_USED = 0
    ZONE_IN_USE = (1 << 0)
    ZONE_ALARM = (1 << 1)
    ZONE_BYPASS = (1 << 2)
    ZONE_FAULT = (1 << 3)

    def __init__(self, host, port=18034):
        """
        :param host: host of the iAlarm security system (e.g. its IP address)
        :param port: port of the iAlarm security system (should be '18034')
        """
        self.host = host
        self.port = port
        self.seq = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.open_connection()

    def open_connection(self) -> None:
        self.seq = 0
        try:
            self.sock.connect((self.host, self.port))
        except (socket.timeout, OSError):
            self.sock.close()
            raise Exception('Could not connect the alarm system')

    def _send_request_list(self, xpath, command, offset=0, partial_list=None):
        if offset > 0:
            command['Offset'] = 'S32,0,0|%d' % offset
        root_dict = self._create_root_dict(xpath, command)
        self._send_dict(root_dict)
        response = self._receive()

        if partial_list is None:
            partial_list = []
        total = self._clean_response_dict(response, '%s/Total' % xpath)
        ln = self._clean_response_dict(response, '%s/Ln' % xpath)
        for i in list(range(ln)):
            partial_list.append(
                self._clean_response_dict(response, '%s/L%d' % (xpath, i)))
        offset += ln
        if total > offset:
            # Continue getting elements increasing the offset
            self._send_request_list(xpath, command, offset, partial_list)
        return partial_list

    def _send_request(self, xpath, command) -> dict:
        root_dict = self._create_root_dict(xpath, command)
        self._send_dict(root_dict)
        response = self._receive()
        return self._clean_response_dict(response, xpath)

    def get_status(self) -> int:
        command = OrderedDict()
        command['DevStatus'] = None
        command['Err'] = None
        alarm_status = self._send_request('/Root/Host/GetAlarmStatus', command)

        command = OrderedDict()
        command['Total'] = None
        command['Offset'] = 'S32,0,0|0'
        command['Ln'] = None
        command['Err'] = None
        zone_status = self._send_request_list('/Root/Host/GetByWay', command)
        if zone_status is not None:
            for zone in zone_status:
                if zone & self.ZONE_ALARM:
                    return self.TRIGGERED

        if alarm_status is not None:
            return int(alarm_status.get("DevStatus"))
        else:
            raise Exception('An error occurred trying to connect the alarm '
                            'system')

    def arm_away(self) -> None:
        command = OrderedDict()
        command['DevStatus'] = 'TYP,ARM|0'
        command['Err'] = None
        self._send_request('/Root/Host/SetAlarmStatus', command)

    def arm_stay(self) -> None:
        command = OrderedDict()
        command['DevStatus'] = 'TYP,STAY|2'
        command['Err'] = None
        self._send_request('/Root/Host/SetAlarmStatus', command)

    def disarm(self) -> None:
        command = OrderedDict()
        command['DevStatus'] = 'TYP,DISARM|1'
        command['Err'] = None
        self._send_request('/Root/Host/SetAlarmStatus', command)

    def cancel_alarm(self) -> None:
        command = OrderedDict()
        command['DevStatus'] = 'TYP,CLEAR|3'
        command['Err'] = None
        self._send_request('/Root/Host/SetAlarmStatus', command)

    def _send_dict(self, root_dict) -> None:
        xml = dicttoxml.dicttoxml(root_dict, attr_type=False, root=False)

        try:
            if self.sock.fileno() == -1:
                self.open_connection()
        except OSError:
            self.open_connection()

        self.seq += 1
        msg = b'@ieM%04d%04d0000%s%04d' % (len(xml), self.seq, self._xor(xml),
                                           self.seq)
        self.sock.send(msg)

    def _receive(self):
        try:
            data = self.sock.recv(1024)
        except (socket.timeout, OSError):
            self.sock.close()
            raise ConnectionError("Connection error")
        # It might happen to receive the err tag before the root, we just
        # remove it because it's not necessary
        decoded = self._xor(data[16:-4]).decode().replace("<Err>ERR|00</Err>",
                                                          "")
        return xmltodict.parse(decoded, xml_attribs=False,
                               dict_constructor=dict,
                               postprocessor=self._xmlread)

    @staticmethod
    def _xmlread(_path, key, value):
        if value is None or not isinstance(value, str):
            return key, value

        err_re = re.compile(r'ERR\|(\d{2})')
        s32_re = re.compile(r'S32,(\d+),(\d+)\|(\d*)')
        str_re = re.compile(r'STR,(\d+)\|(.*)')
        typ_re = re.compile(r'TYP,(\w+)\|(\d+)')
        if err_re.match(value):
            value = int(err_re.search(value).groups()[0])
        elif s32_re.match(value):
            value = int(s32_re.search(value).groups()[2])
        elif str_re.match(value):
            value = str(str_re.search(value).groups()[1])
        elif typ_re.match(value):
            value = int(typ_re.search(value).groups()[1])
        # Else: we are not interested in this value, just keep it as is

        return key, value

    @staticmethod
    def _create_root_dict(path, my_dict=None):
        if my_dict is None:
            my_dict = {}
        root = {}
        elem = root
        plist = path.strip('/').split('/')
        k = len(plist) - 1
        for i, j in enumerate(plist):
            elem[j] = {}
            if i == k:
                elem[j] = my_dict
            elem = elem.get(j)
        return root

    @staticmethod
    def _clean_response_dict(response, path):
        for i in path.strip('/').split('/'):
            try:
                i = int(i)
                response = response[i]
            except ValueError:
                response = response.get(i)
        return response

    @staticmethod
    def _xor(xml):
        sz = bytearray.fromhex('0c384e4e62382d620e384e4e44382d300f382b382b0c5a6234384e304e4c372b10535a0c20432d171142444e58422c421157322a204036172056446262382b5f0c384e4e62382d620e385858082e232c0f382b382b0c5a62343830304e2e362b10545a0c3e432e1711384e625824371c1157324220402c17204c444e624c2e12')
        buf = bytearray(xml)
        for i in range(len(xml)):
            ki = i & 0x7f
            buf[i] = buf[i] ^ sz[ki]
        return buf
