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
from TimelineDefn import TimelineMessage
class BoxType():
    TYPE_DIV = 0
    TYPE_PRE = 1
    TYPE_TEXTBOX = 2
    
    _box_formats = {
        TYPE_DIV : u"""<div class="{}">{}</div>""",
        TYPE_PRE : u"<pre>{}</pre>",
        TYPE_TEXTBOX : u"""<div class="textbox">{}</div>"""
    }
    
class TimelineBox(object):
    '''
    This plugin is similar to the TimelineMessage object with the only
    difference that it generates a box wrapping the text. 
    '''
    
    def __init__(self, box_type, box_class, format_string, *item_names):
        self.message = TimelineMessage( format_string, *item_names )
        self.boxtype = box_type
        self.box_class = box_class
        
    def render(self, item):
        box_fmt = BoxType._box_formats[self.boxtype]
        if self.box_class != None and self.boxtype in [ BoxType.TYPE_DIV ]:
            rendered = box_fmt.render(self.box_class, 
                                      self.message.construct_message(item))
        else:
            rendered = box_fmt.format(self.message.construct_message(item))
        return rendered
        