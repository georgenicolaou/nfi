class TimelineTitle(object):
    def __init__(self,text,icon=None):
        """
        Timeline element text and icon, bot arguments are strings
        """
        self.text = text
        self.icon = icon

class IDataQuery(object):
    def get_items(self):
        raise NotImplementedError
    
class DataQueryCatalog(IDataQuery):
    def __init__(self, catalog_id, query, *item_names ):
        """
        Catalog query to retrieve the subsection containing the items and then
        iterate through that subsection and pull item values.
        """
        self.catalog_id = catalog_id
        self.query = query
        self.item_names = item_names
        return
    
    def get_items(self,store):
        """
        Retrieves the items using the query_catalog function and then sorts them
        into a dictionary for query at a later time.
        
        Arguments:
            - store, the ExtractStore object of this case
        Returns:
            None - on error
            list containing item dictionaries with - containing { name : value }
        """
        subsection = store.query_catalog( self.catalog_id, self.query )
        if subsection == None: return None
        items = []
        for subitem in subsection.get_items():
            row = {}
            for name in self.item_names:
                row[name] = subitem.get_subvaluebyname(name)
            items.append(row)
        return items
        
class DataQueryApp(object):
    def __init__(self, query, *item_names):
        self.query = query
        self.item_names = item_names
    
    def get_items(self,store):
        return None #should we have one for apps??

class TimelineMessage(object):
    def __init__(self, format_string, *item_names):
        """
        Create a message to be printed on the timeline event.
        Arguments:
            - format_string, the format string that will be used with .format
                        make sure that the parameters dont have any names
                        example: "Received call from contact {} with number {}"
            - item_names, variable argument string arguments with the internal
                        names of the values we are looking for.
        """
        self.format_string = format_string
        self.item_names = item_names
    
    def construct_message(self, dataquery_item):
        """
        Constructs the formatted message given the format this object was
        initialized with. The dataquery_item must be a dictionary containing
        a single timeline event.
        
        I thought about error checking fmt but that would hide the issue rather
        than force people to re-write their definitions. So no error checking...
        """
        args = []
        for name in self.item_names:
            if name not in dataquery_item:
                raise KeyError
            args.append(dataquery_item[name])
        return self.format_string.format(*args)
    
class TimelineDefn(object):
    title = None
    data_query = None
    message = None
    plugins = []
    def __init__(self, title, data_query, datefield, messages, plugins=None):
        """
        Timeline definition object that tells the system where to locate items
        to construct a timeline entity.
        Arguments:
            - title, a TimelineTitle object
            - data_query, a list of DataQueryCatalog or DataQueryApp objects
                            that point to the location where the system can
                            find the items and construct an internal dictionary
                            with those items.
            - datefield, a string containing the internal name of the item that
                        contains the timestamp which will be used to place this
                        timeline entity.
            - messages, a TimelineMessage object containing information on how
                        to construct the message field of the timeline entity.
                        Or a list of TimelineMessage bojects
            - plugins, a list containing any additional plugins that should be
                        executed and placed after the message. Plugins include,
                        maps, code boxes, etc.
        """
        self.title = title
        self.data_query = data_query
        self.datefield = datefield
        if type(messages) != list:
            messages = [messages]
        self.messages = messages
        if plugins != None:
            self.plugins = plugins
    
    def get_title(self):
        return self.title.text
    def get_plugins(self):
        return self.plugins
    def get_icon(self):
        return self.title.icon
    def get_query(self):
        return self.data_query
    
    def get_messageobjects(self):
        return self.messages
        
        