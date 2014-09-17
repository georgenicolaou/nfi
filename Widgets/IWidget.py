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
class IWidget(object):
    module_id = None
    module_name = None
    
    def __init__(self):
        return
    
    def _render_widget( self, id, lookup, col_size, data ):
        print "[Error]: Widget render function not overloaded"
        return None
        
    def _render(self,id):
        print "[Error]: Widget render function not overloaded"
        return None

    def set_size(self,size):
        self.col_size = size
        
    def set_title(self,title):
        self.title = title