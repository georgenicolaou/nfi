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
class IMainModule(object):
    def __init__(self, params):
        '''
        Constructor
        '''
        
class MenuEntry(object):
    name = "N/A"
    icon = None
    link = "#"
    content = []
    def __init__(self, name, link, icon=None, content=None ):
        self.name = name
        self.icon = icon
        self.link = link
        if content == None:
            self.content = []
        else:
            self.content = content
        
    #Overload me
    def get_menuentry_list(self,store):
        return []