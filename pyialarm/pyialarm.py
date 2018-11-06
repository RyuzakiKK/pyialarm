import logging

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)


class IAlarm(object):
    """
    Interface the iAlarm security systems.
    """

    ARMED_AWAY = 1
    ARMED_STAY = 2
    DISARMED = 3
    CANCEL = 4
    TRIGGERED = 5

    def __init__(self, username, password, url):
        """
        :param username: iAlarm username (should be 'admin')
        :param password: iAlarm password
        :param url: url of the iAlarm security system
        """
        self.username = username
        self.password = password
        self.url = url

    def authenticate(self):
        """ Apparently the web interface doesn't use cookies or local/session storage """
        pass

    def get_status(self):
        status = None
        try:
            r = requests.get(self.url + '/RemoteCtr.htm', auth=(self.username, self.password))
        except requests.exceptions.ConnectionError:
            log.error("Connection error")
        else:
            text = r.text
            tree = BeautifulSoup(text, 'html.parser')
            if self.is_triggered(tree):
                status = self.TRIGGERED
            else:
                state_line = tree.find(selected="selected")
                if state_line:
                    status = state_line["value"]
        return status

    def arm_away(self):
        self.send_command(self.ARMED_AWAY)

    def arm_stay(self):
        self.send_command(self.ARMED_STAY)

    def disarm(self):
        self.send_command(self.DISARMED)

    def cancel_alarm(self):
        self.send_command(self.CANCEL)

    def send_command(self, command_type):
        form_data = {'Ctrl': str(command_type), 'BypassNum': '00', 'BypassOpt': '0'}
        try:
            requests.post(self.url + '/RemoteCtr.htm', auth=(self.username, self.password), data=form_data)
        except requests.exceptions.ConnectionError:
            raise Exception('Could not connect the alarm system')

    @staticmethod
    def is_triggered(tree):
        script = tree.find("script")
        array_string = None
        for line in script.text.split('\n'):
            if "var ZoneMsg" in line:
                array_string = line
                break

        if array_string:
            array_string = array_string.partition('(')[-1].rpartition(')')[0]
            status = array_string.split(",")
            status = list(map(int, status))

            for zone in status:
                if zone & 3:
                    return True

        return False
