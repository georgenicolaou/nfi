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
from IWidget import IWidget
import json

class TimeGraph(IWidget):
    module_id = 2
    module_name = "Timegraph"
    def __init__(self):
        self.template = "widget_timegraph.html"
        self.col_size = 12
        self.height = 500
        self.data = []
        self.title = ""
        self.lanes = []
        self.lane_ids = 0
        self.items = []
        self.item_ids = 0
        return
    
    def _render_widget(self, widget_id, lookup, col_size, height, title, data):
        tmpl = lookup.get_template(self.template)
        return tmpl.render_unicode(widget_id, col_size, height, title, 
                                   json.dumps(data))
    
    def _render(self, widget_id, lookup):
        self.data = {"lanes":self.lanes,"items":self.items}
        tmpl = lookup.get_template(self.template)
        return tmpl.render_unicode(widget_id, self.col_size, self.height, 
                                   self.title, json.dumps(self.data))
        
    def _get_item_id(self):
        ret = self.item_ids
        self.item_ids += 1
        return ret
    
    def _get_lane_id(self):
        ret = self.lane_ids
        self.lane_ids += 1
        return ret
    
    def add_lane(self, label):
        lane = {
            "id": self._get_lane_id(),
            "label": label
        }
        self.lanes.append(lane)
        return lane["id"]
        
    def add_item(self, lane, start, end, descr):
        '''
        lane - lane id returned from add_lane()
        start - unix timestamp
        end - unix timestamp
        descr - description
        '''
        item = {
            "id": self._get_item_id(),
            "class": "past",
            "desc": descr,
            "start": start,
            "end": end,
            "lane": lane
        }
        self.items.append(item)
        
    def set_height(self,height):
        self.height = height