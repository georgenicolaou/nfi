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
import cherrypy, os
import Widgets
from Catalog import Catalog
from mako.lookup import TemplateLookup

class Widget(object):
    widget_id = -1
    title = ""
    size = 0
    data_func = None
    def __init__(self,widget_id, title,size,data_func):
        self.widget_id = widget_id
        self.title = title
        self.size = size
        self.data_func = data_func
        
class Dashboard(object):

    widgets = []
    def __init__(self,case):
        
        self.widgets = [
            Widget( Widgets.PIE_CHART, "Most calls from/to", 4, 
                    self._top_called_person ),
            Widget( Widgets.PIE_CHART, "Overall time spend in calls", 4, 
                    self._most_lengthy_conversations ),
            Widget( Widgets.PIE_CHART, "Top used Apps", 4, 
                    self._top_used_apps ),
            Widget( Widgets.TABLE, "Device Accounts", 6, 
                    self._get_device_accounts ),
            Widget( Widgets.TABLE, "Device Info", 6, self._get_device_info )
        ]
        self.case = case
        return
        
    @cherrypy.expose
    def index(self, case_id):
        store = self.case.get_store(case_id)
        html = u"""
        <h3>Dashboard</h3><hr />
        """
        for wdef in self.widgets:
            widget = Widgets.get_widget(wdef.widget_id)
            if widget == None: continue
            widget.set_title( wdef.title )
            widget.set_size( wdef.size )
            res = wdef.data_func(widget,store)
            if res:
                html += Widgets.render_widget_object(widget)
        return html
            
    def _top_used_apps(self, widget, store):
        usage_stats = store.query_catalog( Catalog.CATALOG_LOGS, 
                                           "usage_stats.usage_stats")
        if usage_stats == None: return False
        apps = store.store
        app_usage = {}
        for stat in usage_stats.subsection_items:
            activity = stat.get_subvaluebyname("activity_name")
            for app in apps:
                if activity.startswith(app.name):
                    if app.cname != "Unknown":
                        appname = app.cname
                    else:
                        appname = app.name
                    if appname in app_usage:
                        app_usage[appname] += 1
                    else:
                        app_usage[appname] = 1
                    break
        
        for app,num_used in app_usage.iteritems():
            widget.add_item( app, num_used )
        widget.set_hideperc(3)
        return True
    
    def _top_called_person(self, widget, store):
        contacts = store.query_catalog( Catalog.CATALOG_COMMS, 
                                       "contacts.contacts")
        contacts_covered = []
        for contact in contacts.subsection_items:
            name = contact.get_subvaluebyname("name")
            times = contact.get_subvaluebyname("times_contacted")
            if times == 0: continue
            if name in contacts_covered: continue
            contacts_covered.append(name)
            widget.add_item( name, times )
        widget.set_hideperc(2)
        return True
    
    def _most_lengthy_conversations(self, widget, store):
        ok = False
        calls = store.query_catalog( Catalog.CATALOG_COMMS, "telephony.calls")
        if calls == False: return False
        call_totals = {}
        for call in calls.subsection_items:
            name = call.get_subvaluebyname("name")
            if name == None:
                name = call.get_subvaluebyname("number")
            duration = call.get_subvaluebyname("duration")
            if duration > 0: ok = True
            if type(duration) != int:
                if type(duration) not in [str, unicode]: continue
                if duration.isdigit() == False: continue
                duration = int(duration)
            if name in call_totals:
                call_totals[name] += duration
            else:
                call_totals[name] = duration
        for name, duration in call_totals.iteritems():
            widget.add_item( name, duration)
        widget.set_hideperc(2)
        return ok
    
    def _get_device_accounts(self,widget,store):
        accounts = store.query_catalog( Catalog.CATALOG_DEVINFO, 
                                        "accounts.accounts" )
        if accounts == None: return False
        widget.set_header(["Account Name", "Type"])
        for account in accounts.subsection_items:
            name = account.get_subvaluebyname("name")
            atype = account.get_subvaluebyname("type")
            widget.add_item([name,atype])
        return True
    
    def _get_device_info(self,widget,store):
        widget.set_keyvalue(True)
        ok = False
        
        """
        Handle screen lock info
        """
        lock = store.query_catalog( Catalog.CATALOG_DEVINFO, 
                                    "screen_lock.lock_settings" )
        if lock != None:
            ok = True
            lock_type = None
            pin = lock.find_item_by_name("password_hash")
            pattern = lock.find_item_by_name("gesture_hash")
            if pin != None and len(pin.item_value) != 0:
                lock_type = "PIN"
            elif pattern != None and len(pattern.item_value) != 0:
                lock_type = "Pattern"
            
            widget.add_item(["Lock Type", lock_type])
            if lock_type == "PIN":
                pquality = lock.find_item_by_name("lockscreen.password_type")
                if pquality != None:
                    widget.add_item(["Password Quality", pquality.item_value])
            
            owner_info = lock.find_item_by_name("lock_screen_owner_info")
            if owner_info != None:
                widget.add_item(["Lock Screen Message", owner_info.item_value])
        
        """
        Handle WiFi info
        """
        wifi_nets = store.query_catalog( Catalog.CATALOG_NETWORKING, 
                                    "wifi_info.connected_numbers" )
        if wifi_nets != None:
            ok = True
            widget.add_item(["# Connected Wifi Networks", 
                             len(wifi_nets.subsection_items)])
        
        wifi_tether = store.query_catalog( Catalog.CATALOG_NETWORKING, 
                                           "wifi_tethering" )
        
        if wifi_tether != None:
            ok = True
            apname = wifi_tether.find_item_by_name("network_name")
            if apname != None:
                widget.add_item(["WiFi Tethering APN", apname.item_value])
            dnsmasq = store.query_catalog( Catalog.CATALOG_NETWORKING, 
                                           "dhcp_info.dnsmasq_leases" )
            if dnsmasq != None:
                widget.add_item(["Total Connected Clients", 
                                 len(dnsmasq.subsection_items)])
        
        bt = store.query_catalog( Catalog.CATALOG_NETWORKING, 
                                  "bluetooth_info.paired_devices" )
        if bt != None:
            ok = True
            widget.add_item(["# Bluetooth Paired Devices", 
                             len(bt.subsection_items)])
        
        contacts = store.query_catalog( Catalog.CATALOG_COMMS, 
                                        "contacts.contacts" )
        if contacts != None:
            ok = True
            widget.add_item(["Total Contacts", len(contacts.subsection_items)])
        
        calls = store.query_catalog( Catalog.CATALOG_COMMS, "telephony.calls" )
        if calls != None:
            ok = True
            widget.add_item(["Total Calls", len(calls.subsection_items)])
        
        sms = store.query_catalog( Catalog.CATALOG_COMMS, 
                                   "telephony.sms_messages" )
        if sms != None:
            ok = True
            widget.add_item(["Total SMS", len(sms.subsection_items)])
            
        return ok    
    def _usage_infographics(self,widget,store):
        calls = store.query_catalog( Catalog.CATALOG_COMMS, "telephony.calls" )
        got_items = False
        #XXX consider icons
        if calls != None:
            got_items = True
            lane_id = widget.add_lane("Calls")
            for call in calls.subsection_items:
                start = call.get_subvaluebyname("date")
                end = start + call.get_subvaluebyname("duration")
                name = call.get_subvaluebyname("name")
                number = call.get_subvaluebyname("number")
                if name != None:
                    item_label = "{} ({})".format(name,number)
                else:
                    item_label = number
                widget.add_item( lane_id, start, end, item_label )
        smss = store.query_catalog( Catalog.CATALOG_COMMS, 
                                    "telephony.sms_messages")
        if smss != None:
            got_items = True
            lane_id = widget.add_lane("SMS")
            for sms in smss.subsection_items:
                start = sms.get_subvaluebyname("date")
                end = start+1
                item_label = "{}:{}".format( sms.get_subvaluebyname("type"), 
                                             sms.get_subvaluebyname("address"))
                widget.add_item( lane_id, start, end, item_label )
        
        return got_items