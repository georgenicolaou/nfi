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
import ConfigParser,os

class SystemSettings(object):

    default_settings = {
        "timezone": { "type": "str", "default": "local" },
        "tmpdir" : {"type": "str", "default": "/tmp" }
    }
    
    settings = {}
    
    store_file = "nfi.cfg"
    section = "Global"
    
    def __init__(self, store_file=None):
        if store_file != None:
            self.store_file = store_file
        self.config = ConfigParser.RawConfigParser()
        self.load()
        return
    
    def set_storefile(self, path):
        self.store_file = path
        
    def load(self):
        if os.path.exists(self.store_file) == False:
            self.default()
            self.save()
            return
        
        self.config.read( self.store_file )
        for settings_name,descr in self.default_settings.iteritems():
            if descr["type"] == "str":
                val = self.settings[settings_name] = self.config.get( 
                                                self.section, settings_name )
            elif descr["type"] == "int":
                val = self.settings[settings_name] = self.config.getint( 
                                                self.section, settings_name )
            elif descr["type"] == "float":
                val = self.settings[settings_name] = self.config.getfloat( 
                                                self.section, settings_name )
            elif descr["type"] == "bool":
                val = self.settings[settings_name] = self.config.getboolean( 
                                                self.section, settings_name )
            else:
                val = descr["default"]
            if val == None:
                print "GOT None Settings Value"
                val = descr["default"]
            self.settings[settings_name] = val
        return
    
    def save(self):
        for name,val in self.settings.iteritems():
            self.config.set( self.section, name, val )
        try:
            f = open(self.store_file,"wb")
            self.config.write(f)
            f.close()
        except:
            print "[Error] Unable to save settings file"
            return False    
        return True
    
    def default(self):
        self.config.add_section(self.section)
        for name, descr in self.default_settings.iteritems():
            self.config.set( self.section, name, descr["default"] )
        return
    
    def get_all_settings(self):
        return self.settings
    
    def set(self,name,value):
        if name in self.settings:
            self.settings[name] = value
    
    def get(self,name):
        if name in self.settings:
            return self.settings[name]
        if name in self.default_settings:
            return self.default_settings[name]["default"]
        return None
        