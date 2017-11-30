import logging

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)


class IAlarm(object):
    """
    Interface the iAlarm security systems.
    """

    ARMED_AWAY = 1
    ARMED_STAY_NIGHT = 2
    DISARMED = 3

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
        # r = requests.get(self.url, auth=(self.username, self.password))
        # self.cookie = r.cookies

    def get_status(self):
        try:
            r = requests.get(self.url + '/RemoteCtr.htm', auth=(self.username, self.password))
        except requests.exceptions.ConnectionError:
            return None
        text = r.text
        tree = BeautifulSoup(text, 'html.parser')
        state_line = tree.find(selected="selected")
        if state_line:
            return state_line["value"]
        else:
            return None

    def arm_away(self):
        self.arm(self.ARMED_AWAY)

    def arm_stay_night(self):
        self.arm(self.ARMED_STAY_NIGHT)

    def disarm(self):
        self.arm(self.DISARMED)

    def arm(self, arm_type):
        form_data = {'Ctrl': str(arm_type), 'BypassNum': '00', 'BypassOpt': '0'}
        try:
            r = requests.post(self.url + '/RemoteCtr.htm', auth=(self.username, self.password), data=form_data)
        except requests.exceptions.ConnectionError:
            raise Exception('Could not connect the alarm system')
