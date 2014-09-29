import Catalog
from IAuxiliary import IAuxiliary
from AndroidMisc import Packages, UsageStats

from TimelineDefn import DataQueryCatalog, DataQueryApp
from Android.AndroidTimelineDefn import timeline
from Timeline import TimelineItem

class AndroidTimeline(IAuxiliary):
    extract_store = None
    pq = None
    name = "AndroidTimeline"
    index = 100000
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
        self.timeline = self.extract_store.create_timeline()
        
    def add_timeline_events(self, tdefn):
        query = tdefn.get_query()
        data_items = query.get_items(self.extract_store)
        if data_items == None:
            self.selfprint("Query item not found")
            return
        if len(data_items) == 0:
            self.selfprint("Query returned no results")
            return
        
        #title, icon, date, info
        messageobjects = tdefn.get_messageobjects()
        pluginobjects = tdefn.get_plugins()
        for row in data_items:
            date = row[tdefn.datefield]
            if type(date) != int:
                try:
                    date = int(date)
                except:
                    continue
            if date == 0: continue
            msges = []
            plugins = []
            for single_msg in messageobjects:
                msges.append(single_msg.construct_message(row))
            for plugin in pluginobjects:
                plugins.append( plugin.render(row) )
            #should probably allow multiple messages
            timeline_item = TimelineItem( tdefn.get_title(), tdefn.get_icon(), 
                                          row[tdefn.datefield], msges, plugins)
            self.timeline.add_item(timeline_item)
        
    def begin(self):
        for tdefn in timeline:
            self.selfprint("Generating timeline for " + tdefn.title.text )
            self.add_timeline_events(tdefn)
        return True