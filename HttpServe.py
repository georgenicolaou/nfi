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
from cherrypy import tools
from cherrypy._cpdispatch import Dispatcher
#from mako.template import Template
from mako.lookup import TemplateLookup
from DBHandler import DBHandler
import MiscUtils
import os
from copy import copy
import ExtractStore
import json, time, shutil
import cPickle
#import traceback,sys,code
from Catalog import Catalog
from Dashboard import Dashboard
from AppExplorer import AppExplorer
from TimelinePlugin import TimelinePlugin
from Android.AndroidScanner import AndroidScanner
from multiprocessing import Queue
from threading import Thread
import Debug, SystemSettings
import Includes

localdb = Includes.MAINDB_FILEPATH

lookup = TemplateLookup(directories=["_html"], output_encoding='utf-8', 
                        encoding_errors='ignore') #encoding_errors='replace'
current_dir = os.path.dirname(os.path.abspath(__file__))
document_root = os.path.join(current_dir,'_html')
import cherrypy
config = {
    '/': {
        'tools.staticdir.root': current_dir,
        'tools.staticdir.debug': True,
        'tools.caching.on': False,
    },
    '/case' :{
        'tools.staticdir.root': current_dir,
        'tools.staticdir.debug': True,
        'tools.caching.on': False
    },
    '/css': {
        'tools.staticdir.on':True,
        'tools.staticdir.dir':os.path.join(document_root,'css')
    },
    '/fonts': {
        'tools.staticdir.on':True,
        'tools.staticdir.dir':os.path.join(document_root,'fonts')
    },
    '/js': {
        'tools.staticdir.on':True,
        'tools.staticdir.dir':os.path.join(document_root,'js')
    },
    '/images': {
        'tools.staticdir.on':True,
        'tools.staticdir.dir':os.path.join(document_root,'images')
    },
    '/src-min': {
        'tools.staticdir.on':True,
        'tools.staticdir.dir':os.path.join(document_root,'src-min')
    },
}


class Case(object):    
    def __init__(self, store=None,db=None, modules=None, settings=None ):
        if store != None:
            self.stores = {store}
        else:
            self.stores = {}
        self.db = db
        self.catalog_defn = {}
        self.modules = modules
        self.settings = settings
        
    def set_modules(self, modules_array):
        self.modules = modules_array
        
    def get_store(self,case_id,stop_on_error=True):
        if case_id in self.stores:
            return self.stores[case_id]
        
        if stop_on_error:
            raise cherrypy.HTTPError(415,json.dumps({"msg":"Case not loaded",
                                                 "id":case_id}))
        return None
    
    def add_store(self,store,case_id=None):
        self.stores[case_id] = store
    
    def error_415(self, status,message,traceback,version):
        message = json.loads(message)
        tmpl = lookup.get_template("415.html")
        return tmpl.render_unicode(message["msg"],message["id"])
        
    @cherrypy.expose
    def doscan(self,case_id):
        caseobj = self.db.get_cases(case_id)[0]
        #XXX add column in caseobj to distinguish between case types
        q = Queue()
        parser = AndroidScanner(q, settings=self.settings)
        self.parser = parser
        def run_me():
            yield """
                <script type="text/javascript">
                    function stb() {
                        window.scrollBy(0,document.body.scrollHeight);
                    }
                    var success = true;
                </script>
                <style>body {color:#fff;font-family: monospace;}</style>
                <pre>"""
            args = (caseobj["case_appsmount"],)
            p = Thread(target=parser.begin_scan, args=args)
            p.start()
            while True:
                res = q.get()
                if res == "FIN":
                    break
                elif res == "FINERR":
                    yield "<b>Error occurred, canceling scan!<b>"
                    yield "<script>success = false;</script>"
                    self.db.remove_case(caseobj["case_id"])
                    return
                yield res + "\n<script>stb();</script>"
            yield "<b>Finished, Saving Content please wait...</b>"
            yield "</pre>"
            store = parser.get_extractedstore()
            storepath = store.gen_storepath( caseobj["case_name"], 
                                                       caseobj["case_id"] )
            self.db.add_case_storepath( caseobj["case_id"], storepath )
            store_file = store.save_store( storepath )
            self.db.add_case_file(case_id, store_file, 
                MiscUtils.genfilesig(store_file))
            self.add_store(store, case_id)
            #self.add_scanresults = store
        return run_me()
    doscan._cp_config = {'response.stream': True}
    
    @cherrypy.expose
    def scan(self, *args, **kw ):
        case_id = args[0]
        caseobj = self.db.get_cases(case_id)
        tmpl = lookup.get_template("scan.html")
        return tmpl.render_unicode(caseobj=caseobj[0])
        
    @cherrypy.expose
    def index(self,case_id):
        caseobj = self.db.get_cases(case_id)[0]
        store = self.get_store(case_id)
        if store == None:
            store = self.parser.get_extractedstore()
        tmpl = lookup.get_template("case.html")
        return tmpl.render_unicode(modules=self.modules,case=caseobj, 
                                   store=store,
                                   settings=self.settings)
    
        if store == None:
            return tmpl.render_unicode(applications=None)
        return tmpl.render_unicode(applications=store.store)
    
    """
    Case specific functions ---------------------------------------------------
    """
    @cherrypy.expose
    def changesettings(self, case_id, *args, **kw ):
        import copy
        
        newsettings = copy.copy(self.settings)
        for name,val in kw.iteritems():
            newsettings.set( name, val )
        storepath = self.db.get_case_storepath(case_id)
        cfgpath = os.path.join( storepath, Includes.CASE_SETTINGSFILENAME )
        newsettings.set_storefile(cfgpath)
        newsettings.save()
        self.settings = newsettings
        return json.dumps({"success":1})
    
    @cherrypy.expose
    def load(self,case_id):
        store = self.get_store(case_id,False)
        cherrypy.response.cookie["case_id"] = case_id
        if store == None:
            store = ExtractStore.ExtractStore()
            self.add_store(store,case_id)
            case_file = self.db.get_case_file(case_id, True)
            case_store = self.db.get_case_storepath(case_id)
            tmpl = lookup.get_template("case.html")
            if case_file == None:
                cherrypy.response.status = 404
                return tmpl.render_unicode(applications=None,error="Show Form")
            
            filename = case_file["cf_location"]
            if os.path.exists(filename) == False:
                storepath = os.path.join("store", filename)
                if os.path.exists(storepath) == False:
                    cherrypy.response.status = 404
                    return tmpl.render_unicode(applications=None,
                                               error="App Not Found")
                filename = storepath
            store.load_store(filename) #XXX HackerCheck (signature)
            settings_path = os.path.join( case_store, 
                                          Includes.CASE_SETTINGSFILENAME ) 
            if os.path.exists(settings_path):
                self.settings = SystemSettings.SystemSettings( settings_path )
        raise cherrypy.HTTPRedirect("/case/index/"+case_id) #XXX HackerCheck
        
    @cherrypy.expose
    def timeline(self, case_id):
        tmpl = lookup.get_template("case_timeline.html")
        return tmpl.render_unicode(case_id=case_id)
    
class Root(object):
    def __init__(self, db, settings, direct=False):
        self.db = db
        self.settings = settings

    @cherrypy.expose
    def index(self):
        tmpl = lookup.get_template("index.html")
        cases = self.db.get_cases()  
        return tmpl.render_unicode(cases=cases, settings=self.settings)
    
    @cherrypy.expose
    def getofficers(self):
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(self.db.get_officers())
    
    @cherrypy.expose
    def addofficer(self, name, badge=None, *args, **kw):
        self.db.add_officer(name, badge)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps({"success":1})
    
    @cherrypy.expose
    def delcase(self, case_id):
        storepath = self.db.get_case_storepath(case_id)
        try:
            shutil.rmtree(storepath)
        except:
            print "Unable to delete: {}".format(storepath)
        self.db.remove_case(case_id)
        return json.dumps({"success":1})
        
    @cherrypy.expose
    def createcase(self, casename, officers, casecomments, ctype, apps, 
                   system=None ):
        #print "casename: {casename} officers: {officers} comments: {comments} type: {ctype} apps: {apps} system: {system}".format(casename=casename,officers=str(officers),ctype=ctype,apps=apps,system=system,comments=casecomments)
        if not type(officers) is list:
            officers = [officers]
        case_id = self.db.create_case(casename, officers, casecomments, ctype, 
                                      apps, system)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps({"success":1, "case_id": case_id})
    
    @cherrypy.expose
    def changesettings(self, *args, **kw ):
        if kw == None or len(kw) == 0:
            return json.dumps({"success": 0})
        
        for name,val in kw.iteritems():
            self.settings.set( name, val )
        self.settings.save()
        
        return json.dumps({"success": 1})
    
class HttpServe(object):
    def __init__(self,extractstore=None,port="8080"):
        self.extractstore = extractstore
        self.modules = [ Catalog, AppExplorer, TimelinePlugin ]
        self.port = int(port)
        self.settings = SystemSettings.SystemSettings()
        return
        
    def serve(self):
        self.db = DBHandler(localdb)
        cherrypy.engine.signal_handler.subscribe()
        #homepage = Homepage()
        #cherrypy.tree.mount(homepage, config=config)
        #cherrypy.tools.staticdir.debug = True
        cherrypy.config.update({
            'server.socket_host':'0.0.0.0',
            'server.socket_port': self.port,
            'log.screen':True,
            'checker.on': False
        })
        
        direct = False
        if self.extractstore != None:
            case = Case(self.extractstore, settings=self.settings)
        else:
            case = Case(None,self.db, settings=self.settings)
        
        cherrypy.config.update({'error_page.415':case.error_415})
        init_modules = []
        for module in self.modules:
            init_modules.append(module(lookup,case,settings=self.settings))
        case.set_modules(init_modules)
        cherrypy.tree.mount(Root(self.db, self.settings, direct), config=config)
        cherrypy.tree.mount(case, "/case/", config=config)
        
        dbg = Debug.Debug(lookup,case)
        cherrypy.tree.mount(dbg, "/debug", config=config)
        for module in init_modules:
            cherrypy.tree.mount( module, "/" + module.internal_name, 
                                 config=config )
        cherrypy.tree.mount( Dashboard(case), "/dashboard", config=config )
        #cherrypy.tree.mount(Homepage(None), "/case", config=config)
        if hasattr(cherrypy.engine, "signal_handler"):
            cherrypy.engine.signal_handler.subscribe()
        if hasattr(cherrypy.engine, "console_control_handler"):
            cherrypy.engine.console_control_handler.subscribe()
        cherrypy.engine.start()
        cherrypy.engine.block()
