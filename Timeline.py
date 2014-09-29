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
import time, bisect,sys
from datetime import datetime
from datetime import date

class TimelineItem(object):
    
    title = ""
    icon = ""
    itemclass = ""
    date = 0
    info = []
    plugins = []
    
    def __init__(self, title=None, icon=None, date=None, info=None, 
                 plugins=None ):
        self.title = title
        self.icon = icon
        if date == None: self.date = 0 
        else: self.date = date
        if info == None: self.info = []
        else: self.info = info
        if plugins == None: self.plugins = []
        else: self.plugins = plugins
        return
    
    def __cmp__(self,obj):
        return cmp(self.date,obj.date)
    
class TimelineDate(object):
    day = ""
    month = ""
    items = []
    def __init__(self, day_timestamp, day, month, year, items=None):
        self.day_timestamp = day_timestamp
        self.day = day
        self.month = month
        self.year = year
        if items == None: self.items = []
        else: self.items = items
    
    def add_item(self, item):
        bisect.insort(self.items, item)
    
    def __cmp__(self,obj):
        return cmp(self.day_timestamp, obj.day_timestamp)

class Timeline(object):
    CLASS_SUCCESS = "success"
    CLASS_WARN = "warning"
    CLASS_INFO = "info"
    CLASS_PRIMARY = "primary"
    
    _DATES_KEYFORM = "{day}{month}{year}"
    def __init__(self):
        self.items = []
        self.timeline_dates = {}
        return
    
    def _convertunix(self, unix):
        if type(unix) in [str,unicode]:
            if unix.isdigit(): unix = int(unix)
            else: return None
        return unix
    
    def _get_month_from_unix(self,unix):
        unix = self._convertunix(unix)
        try:
            return datetime.fromtimestamp(unix).strftime('%b')
        except:
            return None
    
    def _get_day_from_unix(self, unix):
        unix = self._convertunix(unix)
        try:
            return datetime.fromtimestamp(unix).strftime('%d')
        except:
            return None
    
    def add_item(self, item):
        item.date = self._convertunix(item.date)
        if item.date == None: return
        dt = datetime.fromtimestamp(item.date)
        try:
            item_day = dt.strftime('%d')
            item_month = dt.strftime('%b')
            item_year = dt.strftime('%Y')
        except:
            return
        
        key = self._DATES_KEYFORM.format(day=item_day,month=item_month,
                                         year=item_year)
        if key in self.timeline_dates:
            self.timeline_dates[key].add_item(item)
        else:
            day_date = datetime.fromtimestamp(item.date).date()
            day_tsmp = time.mktime(day_date.timetuple())
            timeline_date = TimelineDate( day_tsmp, item_day, item_month, 
                                          item_year, [item] )
            bisect.insort(self.items, timeline_date)
            self.timeline_dates[key] = timeline_date
        return
    
    def _get_beginning_ofmonth(self):
        today = date.today()
        fdmonth = date(today.year, today.month, 1)
        return int(time.mktime(fdmonth.timetuple()))
    
    def get_items(self, start=None, end=None, force_month=False ):
        if force_month == False:
            if start == None and end == None:
                return self.items
        
        start = self._convertunix(start)
        end = self._convertunix(end)
        
        if start == None:
            start = self._get_beginning_ofmonth()
        if end == None:
            end = int(time.time())
        print "Start: {}({}) end: {}({})".format(type(start),start,type(end),end)        
        res = [ i for i in self.items if i.day_timestamp >= start and 
                i.day_timestamp <= end ]
        print "Got: {}".format(len(res))
        return res