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
import time,datetime

class TimelineItem(object):
    
    title = ""
    icon = ""
    itemclass = ""
    date = 0
    info = []
    
    def __init__(self, title=None, icon=None, date=None, info=None ):
        self.title = title
        self.icon = icon
        if date == None: self.date = 0 
        else: self.date = date
        if info == None: self.info = []
        else: self.info = info
        return
    
class TimelineDate(object):
    day = ""
    month = ""
    items = []
    def __init__(self, day, month, items=None):
        self.day = day
        self.month = month
        if items == None: self.items = []
        else: self.items = items
    
    def add_item(self, item):
        self.items.append(item)

class Timeline(object):
    CLASS_SUCCESS = "success"
    CLASS_WARN = "warning"
    CLASS_INFO = "info"
    CLASS_PRIMARY = "primary"
    
    _DATES_KEYFORM = "{day}{month}"
    def __init__(self):
        self.items = []
        self.timeline_dates = {}
        return
    
    def _convertunix(self, unix):
        if type(unix) == str:
            if unix.isdigit(): unix = int(unix)
        return unix
    
    def _get_month_from_unix(self,unix):
        unix = self._convertunix(unix)
        return datetime.datetime.fromtimestamp(unix).strftime('%b')
    
    def _get_day_from_unix(self, unix):
        unix = self._convertunix(unix)
        return datetime.datetime.fromtimestamp(unix).strftime('%d')
    
    def add_item(self, item):
        item_day = self._get_day_from_unix(item.date)
        item_month = self._get_month_from_unix(item.date)
        key = self._DATES_KEYFORM.format(day=item_day,month=item_month)
        if key in self.timeline_dates:
            self.timeline_dates[key].add_item(item)
        else:
            timeline_date = TimelineDate( item_day, item_month, [item] )
            self.items.append(timeline_date)
            self.timeline_dates[key] = timeline_date
        return
    
    def get_items(self):
        return self.items