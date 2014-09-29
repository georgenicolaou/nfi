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
import os, string
import Includes
from Timeline import Timeline

TYPE_NONE = 0
TYPE_EMPTY = 1
TYPE_TABLE = 2
TYPE_DATA = 3
TYPE_STRING = 4
TYPE_MULTI = 5
TYPE_XML = 6
TYPE_IMAGE = 7
TYPE_DATE = 8

STORE_FOLDER = Includes.STORE_FOLDER

"""
http://stackoverflow.com/questions/17809386/
"""
def permissions_to_unix_name(st):
    dic = {'7':'rwx', '6' :'rw-', '5' : 'r-x', '4':'r--', '0': '---'}
    perm = str(oct(st.st_mode)[-3:])
    return '-' + ''.join(dic.get(x,x) for x in perm)


#XXX this should be removed and just use ApplicationFile maybe
class MultiContent(object):
    cname = "Unknown"
    ctype = TYPE_NONE
    content = None
    tbl_info = None
    knowninfo = None
    def __init__(self, ctype, name, content, tbl_info, knowninfo=None):
        self.ctype = ctype
        self.content = content
        self.name = name
        if tbl_info != None:
            self.tbl_info = { c['name']: c['type'] for c in tbl_info }
        else:
            self.tbl_info = None
        self.knowninfo = knowninfo

class ApplicationFile(object):
    name = ""
    ftype = TYPE_NONE
    content = None
    tbl_info = None
    mime = None
    sha256sig = None
    knowninfo = None
    filepath = None
    """
    @var filename: str
    @var ftype: int 
    """
    def __init__(self, filename, ftype, tbl_info=None, knowninfo=None, filepath=None):
        self.name = filename
        self.ftype = ftype
        self.mime = None
        self.filepath = filepath
        if tbl_info != None:
            self.tbl_info = { c['name']: c['type'] for c in tbl_info }
        else:
            self.tbl_info = None
        self.content = None
        self.md5sig = None
        self.sha1sig = None
        self.knowninfo = knowninfo
    
    """
    Attach content data to this file.
    Params:
        - content: The actual content in any type (array,text,etc)
        - ctype: The type of the content if the file's original type is
                    TYPE_MULTY. If not, then no ctype is necessary
    """
    def add_content(self, content, ctype=None, name=None, tbl_info=None, knowntable=None):
        if self.ftype == TYPE_MULTI:
            if self.content == None:
                self.content = []
            mcontent = MultiContent(ctype, name, content, tbl_info, knowntable)
            self.content.append(mcontent)
        else:        
            self.content = content
    
    def add_sig(self, sha256sig):
        self.sha256sig = sha256sig
    
    def set_mime(self,mimestring):
        self.mime = mimestring
        
    def add_stats(self,statsobj):
        self.atime = int(statsobj.st_atime)
        self.ctime = int(statsobj.st_ctime)
        self.mtime = int(statsobj.st_mtime)
        self.uid = statsobj.st_uid
        self.gid = statsobj.st_gid
        self.size = statsobj.st_size
        self.mode = permissions_to_unix_name(statsobj)
    
    def get_multicontent(self,name,ctype=None):
        if self.ftype != TYPE_MULTI:
            return None
        if self.content == None: return None
        for cont in self.content:
            if cont.name == name:
                if ctype != None:
                    if cont.ctype != ctype:
                        return None
                return cont
        return None
     
class ApplicationDirectory(object):
    name = ""
    files = []
    directories = []
    def __init__(self, dirname):
        self.name = dirname
        self.files = []
        self.directories = []
    
    """
    @var appfile: ApplicationFile
    Registers file into directory. The appfile argument should be generated
    by the handler
    """
    def add_file(self, appfile):
        self.files.append(appfile)
        return
    
    def add_dir(self, dirname):
        adir = ApplicationDirectory(dirname)
        self.directories.append(adir)
        return adir
    
    def find_dir(self,dirname):
        for dir in self.directories:
            if dir.name == dirname:
                return dir
        return None
    
    def find_file(self,filename):
        for dirfile in self.files:
            if dirfile.name == filename:
                return dirfile
        return None
    
    def find_all_files(self,filename):
        files = []
        for dirfile in self.files:
            if dirfile.name == filename:
                files.append(dirfile)
        for subdir in self.directories:
            found = subdir.find_all_files(filename)
            if len(found) != 0: files += found
        return files
    
    def find_file_recursieve(self,filename):
        for dirfile in self.files:
            if dirfile.name == filename:
                return dirfile
        for subdir in self.directories:
            found = subdir.find_file_recursieve(filename)
            if found != None: return found
        return None

class Application(object):
    name = ""
    cname = "" #canonical name eg: "Google Chrome"
    totalfiles = 0
    installation_date = None
    directories = []
    permissions = []
    update_date = None
    version = None
    binary = None
    app_user = None
    installer = None
    
    library_path = ""
    
    def __init__(self, package_name, canonical_name):
        self.name = package_name
        self.cname = canonical_name
        self.directories = []
        self.totalfiles = 0
        self.installation_date = None
        self.last_run = None
        self.exec_history = {}
        self.permissions = []
        self.update_date = None
        self.version = None
        self.binary = None
        self.app_user = None
        self.installer = None
        self.library_path = ""
    
    def set_library_path(self,path):
        self.library_path = path
        
    def set_installation_date(self,date):
        self.installation_date = date
        
    def add_root_stats(self, statsobj):
        self.atime = int(statsobj.st_atime)
        self.ctime = int(statsobj.st_ctime)
        self.mtime = int(statsobj.st_mtime)
        self.uid = statsobj.st_uid
        self.gid = statsobj.st_gid
        self.size = statsobj.st_size
        self.mode = permissions_to_unix_name(statsobj)
        
    def add_directory(self, dirname):
        adir = ApplicationDirectory(dirname)
        self.directories.append(adir)
        return adir
    
    def get_install_date(self):
        if self.installation_date != None:
            return self.installation_date
        else:
            return self.ctime


class MiscItem(object):
    item_label = ""
    item_name = None
    item_value = ""
    item_contents = []
    item_type = TYPE_NONE
    
    def __init__(self, item_type, label=None, value=None, item_contents=None, 
                 item_name=None ):
        self.item_label = label
        self.item_value = value
        self.item_type = item_type
        self.item_contents = []
        self.item_name = item_name
        if item_contents != None:
            if self.item_type != TYPE_MULTI:
                print "Error, not a MULTI item type"
            self.item_contents = item_contents
    
    def add_item(self, item):
        self.item_contents.append( item )
    
    def get_subvaluebyname(self, name):
        if self.item_type != TYPE_MULTI: return None
        for item in self.item_contents:
            if item.item_name == name:
                return item.item_value
        return None
    
    def find_subitem_by_name(self, name):
        if len(self.item_contents) == 0: return None
        for subitem in self.item_contents:
            if subitem.item_name == name:
                return subitem
        return None
                
    def add_multiple_items(self, items ):
        if self.item_type != TYPE_MULTI:
            self.item_type = TYPE_MULTI
        if len(self.item_contents) != 0:
            self.item_contents += items
        else:
            self.item_contents = items
    def __str__(self, i=1):
        if self.item_type != TYPE_MULTI:
            return "{}{} = {}\n".format( "\t"*i, self.item_label, self.item_value)
        else:
            ret = ""
            for content in self.item_contents:
                ret += "{}".format( content.__str__(i+1) )
            return ret+"\n"

#XXX add link to parent section and then check if the new section already exists. 
# this would work in cases where we have the same file, named .old
class MiscSubSection(object):
    subsection_name = ""
    subsection_label = ""
    subsection_items = []
    
    def __init__(self, subsection_label, items):
        self.subsection_label = subsection_label.label
        self.subsection_name = subsection_label.internal_name
        self.subsection_items = items
    
    def add_items(self, items):
        self.subsection_items += items
    
    def get_items(self):
        return self.subsection_items
    
    def find_item_by_name(self, item_name):
        for item in self.subsection_items:
            if item.item_name == item_name:
                return item
        return None
            
    def __str__(self):
        ret = "\t{}:\n".format(self.subsection_name)
        for item in self.subsection_items:
            ret += str(item) 
        return ret


class MiscSection(object):
    section_name = ""
    section_label = ""
    subsections = []
    def __init__(self, section_label):
        self.section_label = section_label.label
        self.section_name = section_label.internal_name
        self.subsections = []
        
    def add_subsection(self, subsection ):
        existing_subsection = self.get_subsection( subsection.subsection_name )
        if existing_subsection != None:
            existing_subsection.add_items( subsection.subsection_items )
        else:
            self.subsections.append(subsection)
    
    def add_subsections(self, subsections ):
        for subsection in subsections:
            self.add_subsection( subsection )
        #self.subsections += subsections
    
    def get_subsection(self, subsection_name):
        for subs in self.subsections:
            if subs.subsection_name == subsection_name:
                return subs
        return None
    def __str__(self):
        return "{}:\n{}".format(self.section_name,str(self.subsections))
        
class MiscCatalog(object):
    sections = {}
    catalog_id = 0
    
    def __init__(self, catalog_id):
        self.catalog_id = catalog_id
        self.sections = {}
        
    def add_section(self,section):
        self.sections[section.section_name] = section
    
    def get_section_by_internalname(self, int_name ):
        if int_name in self.sections:
            return self.sections[int_name]
        return None
            
    def get_section(self, section_label, create_new=False ):
        int_name = section_label.internal_name
        if int_name in self.sections:
            return self.sections[int_name]
        if create_new:
            newsection = MiscSection( section_label )
            self.add_section( newsection )
            return newsection
        return None
    
class ExtractStore(object):
    
    store = []
    misc_catalogs = {}
    timeline = None
    def __init__(self):
        self.store = []
        self.misc_catalogs = {}
        return
    
    """
    Add the application's package name in order to generate the appropriate
    structure for this application
    Params:
        - package_name: The application's package name (string)
    """
    def create_application(self, package_name, canonical_name=None):
        app = Application(package_name, canonical_name)
        self.store.append(app)
        return app
    
    def create_timeline(self):
        self.timeline = Timeline()
        return self.timeline
        
    def get_misccatalog(self, catalog):
        if catalog in self.misc_catalogs:
            return self.misc_catalogs[catalog]
        else:
            new_catalog = MiscCatalog(catalog)
            self.misc_catalogs[catalog] = new_catalog
            return new_catalog
            
    def find_application(self, package_name):
        for app in self.store:
            if app.name == package_name:
                return app
        return None
    
    def query_appstore(self,path):
        '''
        XXX not implemented.
        Application queries are slash separated paths to the file or directory
        you wish to retrieve. You may specify your query as:
            com.android.browser/databases/browser2.db
        
        The above query will return the MiscItem file containing the contents
        of browser2.db database file. Alternatively you can specify any file
        you wish.
        
        The code below keeps iterating through an application's directories
        until there are no more directories found. Then it searches through the
        files to find the necessary file.
        
        If you wish to retrieve the application's root directory then 
        '''
        steps = path.split("/")
        steps.reverse()
        
        app = self.find_application( steps.pop() )
        if app == None: return None
        if len(steps) == 0: return app
        
        root = app.directories[0]
        if steps[0] == "" and len(steps) == 0:
            return root
        
        curr_dir = root
        step_file = None
        while len(steps) != 0:
            step_dir = steps.pop()
            if step_dir == "": return curr_dir
            new_dir = curr_dir.find_dir(step_dir)
            if new_dir == None:
                step_file = step_dir
                break
            curr_dir = new_dir
        
        if step_file == None:
            return new_dir
        
        found_file = curr_dir.find_file(step_file)
        
        return found_file
    
    def query_catalog(self, catalog_id, path):
        '''
        Catalog queries are dot separated paths to the catalog. For example
        if you wish to access the a specific catalog just subsection you
        may specify a query as:
            section_name.subsection_name
        
        If you wish to access a specific item then you can specify:
            section_name.subsection_name.item_name
        
        For example accessing available permissions on an Android device would 
        be:
            query_catalog( Catalogs.CATALOG_APPS, 
                            "packages.available_permissions" )
        '''
        if catalog_id not in self.misc_catalogs: return None
        catalog = self.misc_catalogs[catalog_id]
        steps = path.split(".")
        steps.reverse()
        
        section = catalog.get_section_by_internalname( steps.pop() )
        if section == None: return None
        if len(steps) == 0: return section
        
        subsection = section.get_subsection( steps.pop() )
        if subsection == None: return None
        if len(steps) == 0: return subsection
        
        item = subsection.find_item_by_name( steps.pop() )
        if item == None: return None
        if len(steps) == 0: return item
        
        while len(steps) != 0:
            item = item.find_subitem_by_name( steps.pop() )
            if item == None: return None
        return item
    
    def query_app(self, app, path):
        return
    
    def get_store(self):
        return self.store

    """
    ---------------------------------------------------------------------------
    - Store storage and loading
    ---------------------------------------------------------------------------
    """
    def gen_storepath(self, casename, case_id):
        if( os.path.exists(STORE_FOLDER) == False ):
            os.mkdir(STORE_FOLDER)
        valid = "-_.()%s%s" % ( string.ascii_letters, string.digits )
        casename_norm = ''.join( c for c in casename if c in valid )
        casename_norm += "_"+str(case_id) 
        storepath = os.path.join( STORE_FOLDER, casename_norm )
        return storepath
    
    def save_store(self, storepath ):
        import cPickle, time, marshal
        if os.path.exists(storepath) == False:
            os.mkdir( storepath )
        filepath = os.path.join( 
            storepath, time.strftime("%d%m%Y-%H%M%S") )
        filepath_ext = filepath + ".bin"
        cnt = 1
        while os.path.exists(filepath_ext):
            filepath_ext = "{}_{}.bin".format(filepath,cnt)
            cnt += 1  
        with open(filepath_ext,"wb") as storefile:
            #marshal.dump( self.store, storefile)
            cPickle.dump((self.store, self.misc_catalogs, self.timeline), 
                         storefile, cPickle.HIGHEST_PROTOCOL)
        return filepath_ext
            
    def load_store(self, filename):
        import cPickle,marshal
        with open(filename,"rb") as storefile:
            storefile.seek(0)
            #self.store = marshal.load(storefile)
            (self.store, self.misc_catalogs, self.timeline) = cPickle.load(
                                                                    storefile)
            