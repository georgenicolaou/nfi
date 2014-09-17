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
from FileHandlers import *
import re

class MimeGuesser(object):
    gotmagic = True
    getfmime = None
    
    meta = {
        "sqlite3": {"mime": "application/octet-stream", 
                    "desc": "Sqlite 3.x database", "handler":handler_sqlite },
        "bplist": { "handler": handler_bplist },
        "xml": { "mime": "application/xml", "handler":handler_xml },
        "data": { "handler": handle_data },
        "image": { "handler": handle_image },
        "text": { "handler": handle_text },
        "default": { "handler": handle_data }
    }
    
    """
    signatures = {
        "sqlite3":"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00",
        "xml":"\x3c\x3f\x78\x6d\x6c\x20",
        "jpeg":"\xFF\xD8\xFF"
    }
    """
    signatures = {
        "bplist": "^bplist00"
    }
    magicsignatures = {
        "sqlite3":"SQLite 3.*",
        "bplist": "Apple binary property list",
        "xml": "XML.*",
        "image": "(JPEG|PNG|GIF).*",
        "data": "data.*",
        "text": "ASCII.*"
    }
    def localmime_buffer(self, buf):
        for key,value in self.signatures.iteritems():
            if value.match(buf) != None:
                return key
        return None
    
    def localmime(self, file):
        #XXX write code for the above    
        return
    
    def magicmime(self, file):
        mdescr = self.getfmime(file)
        for key in self.magicsignatures.keys():
            if self.magicsignatures[key].match(mdescr):
                return self.meta[key]
        return self.meta["default"]
        #return None
    
    def __init__(self):
        for key in self.magicsignatures.keys():
            self.magicsignatures[key] = re.compile(self.magicsignatures[key])
        for key in self.signatures.keys():
            self.signatures[key] = re.compile(self.signatures[key])
        try:
            import magic
            self.getfmime = magic.from_file
            self.getbmime = magic.from_buffer
        except:
            print "python-magic is not installed (or wrong version)"
            self.gotmagic = False
    
    def get_buffermimetype(self,buf,mime=False):
        result = self.getbmime(buf,mime)
        if result == 'application/octet-stream':
            localres = self.localmime_buffer(buf)
            if localres != None:
                return localres
        return result
    
    def get_filemime(self,filepath,mime=False):
        return self.getfmime(filepath,mime)
    
    def get_handler(self, filepath ):
        info = self.magicmime(filepath)
        if info == None:
            #print "\tNO HANDLER FOR: " + filepath
            return None
        return info["handler"]