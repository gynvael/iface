# -*- coding: utf-8 -*-
__author__ = 'Mariusz "maryush" Witkowski'

import os
import sys
import ConfigParser

config_file = os.path.dirname(__file__)+os.sep+"iface.cfg"

class Config(object):
    """basic operations on config file"""
    cfg = None

    def __init__(self, config_file):
        """class initialization"""
        if not config_file:
            config_file = config_file

        self.cfg = ConfigParser.RawConfigParser()
        self.cfg.read(config_file)

    def get(self, section, name):
        """read value from selected section"""
        try:
            value = self.cfg.get(section, name)
        except:
            value = None
        finally:
            return value

    def getBoolean(self, section, name):
        """getting boolean value"""
        return self.cfg.getboolean(section, name)

    def getInt(self, section, name):
        """getting int value"""
        return self.cfg.getint(section, name)


cfg = Config(config_file)