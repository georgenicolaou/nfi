'''
NFI -- Silensec's Nyuki Forensics Investigator

Copyright (C) 2014  George Nicolaou (george[at]silensec[dot]com)
                    Silensec Ltd.

This file is part of Nyuki Forensics Investigator (NFI).

NFI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NFI is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NFI.  If not, see <http://www.gnu.org/licenses/>.
'''
import re
from IDeviceVersion import IDeviceVersion

class DataTypes(object):
    EMPTY = 0
    DATA = 1
    TEXT = 2
    DATE = 3
    
class IApp(object):
    '''
    classdocs
    '''
    name = "Unknown"
    cname = "Unknown"
    databases = {}
    known = False
    dummyRE = type(re.compile("nfi"))
    version = [-1]
    
    def get_versions(self):
        return self.version
    
    def has_defaultversion(self):
        if IDeviceVersion.DEFAULT_VERSION in self.version:
            return True
        return False
    
    def has_version(self,appversion):
        if appversion in self.version:
            return True
        return False
    
    def get_packagename(self):
        return self.name
    
    def get_canonicalname(self):
        return self.cname
    
    def get_files(self):
        return self.databases
    
    def get_file_info(self, dbname):
        if len(self.databases) == 0:
            return None
        for thisdbname,defn in self.databases.iteritems():
            if type(thisdbname) == type("str"):
                if thisdbname == dbname:
                    return defn
            elif type(thisdbname) == self.dummyRE:
                if thisdbname.match(dbname) != None:
                    return defn
        return None
    
    def set_packagename(self, name):
        self.name = name
    
    def __init__(self):
        return

class KnownTable(object):
    name = None
    sql = None
    converter = None
    knownfields = None
    def __init__(self, table_name, parse_sql, converter=None, knownfields=None ):
        self.name = table_name
        self.sql = parse_sql
        self.converter = converter
        self.knownfields = knownfields