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
from IMainModule import MenuEntry, IMainModule
import cherrypy, ExtractStore, HtmlExtract, json, re, base64
from Catalog import Catalog
from copy import copy
from Timeline import Timeline, TimelineDate, TimelineItem

class AppExplorer(IMainModule):
    APPLICATION_BROWSER = 1
    
    name = "Application Explorer"
    internal_name = "appexplorer"
    
    
    catalogs_info = {
        APPLICATION_BROWSER: { "name": "Browse Apps", "display": True, 
                              "url":"/appsexplorer/", "icon": "fa-archive" }
    }
    
    _menu = [
        MenuEntry( "Explore Apps", "/apps", "fa-archive" ),
        MenuEntry( "Advanced App Filtering", "/filter", "fa-search")
    ]
    
    def get_menuentry_list(self, store, case_id):
        app_names = []
        
        for app in store.store:
            app_names.append( MenuEntry(app.name, 
                                        "/app/{}/{}".format(case_id,app.name)) )
        menu = []
        for entry in self._menu:
            case_entry = MenuEntry( entry.name, entry.link + "/" + str(case_id), 
                           entry.icon )
            if entry.link == "/apps":
                case_entry.content = app_names 
            menu.append(case_entry)
        return menu
    
    def __init__(self, lookup, case, settings):
        '@type lookup: mako.lookup.TemplateLookup'
        self.lookup = lookup
        self.case = case
        self.htmlextract = HtmlExtract.HtmlExtract()
        self.settings = settings
        return
    
    def set_templatelookup(self, lookup):
        '@type lookup: mako.lookup.TemplateLookup'
        self.lookup = lookup


    def _filter_dates(self, store, apps, datefrom, dateto):
        if type(datefrom) != int and datefrom != None:
            if datefrom.isdigit() == False: return None
            datefrom = int(datefrom)
        if type(dateto) != int and dateto != None:
            if dateto.isdigit() == False: return None
            dateto = int(dateto)

                    
        usage_stats = store.query_catalog( Catalog.CATALOG_LOGS, 
                                           "usage_stats.usage_stats" )
        if usage_stats == None: return None
        
        stats_dict = {}
        for stat in usage_stats.subsection_items:
            name = stat.get_subvaluebyname("activity_name")
            if name in stats_dict:
                stats_dict[name].append( stat.get_subvaluebyname("last_run") )
            else:
                stats_dict[name] = [stat.get_subvaluebyname("last_run")]
        
        #Stats that fall under datefrom and dateto
        stat_filtered = []
        for name,dates in stats_dict.iteritems():
            for date in dates:
                fromadd = True
                toadd = True
                try: intdate = int(date) 
                except: continue
                if datefrom != None:
                    if intdate >= datefrom: fromadd = True
                    else: fromadd = False
                if dateto != None:
                    if intdate <= dateto: toadd = True
                    else: toadd = False
                if fromadd and toadd:
                    stat_filtered.append(name)
                    break
        
        apps_filtered = []
        for app in apps:
            for stat in stat_filtered:
                if stat.startswith(app.name):
                    apps_filtered.append(app)
                    break
                    
        return apps_filtered
    
    def _filter_perm(self, apps, permlist):
        apps_filtered = []
        if type(permlist) != list:
            permlist = [permlist]
        for app in apps:
            if set(permlist).issubset(set(app.permissions)):
                apps_filtered.append(app)
        return apps_filtered
    
    def _filter_files_scandir(self, appdir, nametok, root=False):
        add = False
        hints = []
        
        if nametok in appdir.name:
            add = True
            hints.append( appdir.name )
            
        for appfile in appdir.files:
            if nametok in appfile.name:
                add = True
                if root:
                    hints.append('/'+appfile.name)
                else:
                    hints.append( '/'.join([appdir.name,appfile.name]))
        for subdir in appdir.directories:
            tmpadd, tmphints = self._filter_files_scandir(subdir, nametok)
            if tmpadd == True:
                add = True
                for hint in tmphints:
                    if root:
                        hints.append('/'+hint)
                    else:
                        hints.append( '/'.join([appdir.name, hint]))
        return (add,hints)
    
    def _filter_files(self, apps, nametok):
        apps_filtered = []
        hints = {}
        for app in apps:
            add = False
            if nametok in app.name:
                add = True
            
            for appdir in app.directories: #only 1 dir here, root
                tmpadd, tmphints = self._filter_files_scandir(appdir,nametok,
                                                              True)     
                if tmpadd == True:
                    add = True
                    hints[app.name] = tmphints
            if add:
                apps_filtered.append(app) 
        return (apps_filtered,hints)
    
    
    def _filter_text_scanfilecontents(self, appfile, searchtok ):
        
        if appfile.ftype == ExtractStore.TYPE_MULTI:
            res = []
            for cont in appfile.content:
                skiptbl = False
                if cont.ctype == ExtractStore.TYPE_TABLE:
                    for tblrow in cont.content:
                        for colcont in tblrow.values():
                            if colcont != None:
                                if type(colcont) in [str, unicode]:
                                    try:
                                        if searchtok in colcont:
                                            res.append(cont.name)
                                            skiptbl = True
                                            break
                                    except:
                                        pass
                                else:
                                    try:
                                        if searchtok in str(colcont):
                                            res.append(cont.name)
                                            skiptbl = True
                                            break
                                    except:
                                        pass
                        if skiptbl: break
                    if skiptbl: break
                else:
                    try:
                        if searchtok in cont:
                            return True
                    except:
                        pass
            if len(res) == 0: return False
            return res
        else:
            try:
                if searchtok in appfile.content:
                    return True
            except:
                pass
        return False
    
    def _filter_text_scandir(self, appdir, searchtok, root=False):
        add = False
        hints = []
        
        for appfile in appdir.files:
            tmpadd = self._filter_text_scanfilecontents(appfile, searchtok)
            if type(tmpadd) == list:
                add = True
                for tmphint in tmpadd:
                    if root:
                        hints.append( "/{}:: Table: {}".format(appfile.name,tmphint) )
                    else:
                        hint = '/'.join([appdir.name,appfile.name])
                        hints.append( "{}:: Table: {}".format( hint, tmphint ) )
                        
            elif tmpadd == True:
                add = True
                if root:
                    hints.append( '/' + appfile.name )
                else:
                    hints.append( '/'.join([appdir.name,appfile.name]) )
        for subdir in appdir.directories:
            tmpadd, tmphints = self._filter_text_scandir(subdir, searchtok)
            if tmpadd == True:
                add = True
                for hint in tmphints:
                    if root:
                        hints.append( '/'+hint )
                    else:
                        hints.append( '/'.join([appdir.name,hint]) )
        return (add,hints)
    
    def _filter_text(self, apps, searchtok):
        apps_filtered = []
        hints = {}
        
        for app in apps:
            add = False
            for appdir in app.directories: #only 1 dir here, root
                tmpadd, tmphints = self._filter_text_scandir(appdir, searchtok, 
                                                             True)
                if tmpadd == True:
                    add = True
                    hints[app.name] = tmphints
            if add:
                apps_filtered.append(app)
        return (apps_filtered, hints)
    @cherrypy.expose
    def applyfilter(self, case_id, *args, **kw):
        filter_toks = {
            "case_id": None,
            "filesearch" : None,
            "freetext" : None,
            "dateto" : None,
            "datefrom" : None,
            "perm" : None
        }
        
        for arg_name,value in kw.iteritems():
            if arg_name in filter_toks:
                if len(value) != 0:
                    filter_toks[arg_name] = value
        filter_toks["case_id"] = case_id
        hints = {}
        store = self.case.get_store(filter_toks["case_id"])
        if filter_toks["case_id"] == None: return "No Case ID Specified"
        appslist = store.store
        if filter_toks["datefrom"] != None or filter_toks["dateto"] != None:
            tmplist = self._filter_dates( store, appslist, 
                                filter_toks["datefrom"], filter_toks["dateto"] )
            if tmplist != None:
                appslist = tmplist
                
        if filter_toks["perm"] != None:
            appslist = self._filter_perm(appslist, filter_toks["perm"])
        
        if filter_toks["filesearch"] != None:
            appslist, hints = self._filter_files( appslist, 
                                                   filter_toks["filesearch"] )    
        
        if filter_toks["freetext"] != None:
            appslist, newhints = self._filter_text( appslist, 
                                                 filter_toks["freetext"] )
            for appname, hint in newhints.iteritems():
                if appname in hints:
                    hints[appname] += hint
                else:
                    hints[appname] = hint
        
        
        result = []
        for app in appslist:
            res = {
                'app': app.name, 
                'url': "/{}/app/{}/{}".format( self.internal_name, case_id,
                                               app.name )
            }
            
            #http://ishtus-laptop:8080/case/index/40#/appexplorer/view/com.android.providers.contacts/databases/contacts2.db
            if app.name in hints:
                hintslist = []
                for hint in hints[app.name]:
                    hinturl = hint.split("::")[0]
                    hintslist.append({
                        'hint' : hint,
                        'url': "/{}/view/{}/{}{}".format( self.internal_name, 
                                                    case_id, app.name, hinturl )
                    })
                res['hints'] = hintslist
            result.append(res)
        return json.dumps({"success":1, "results":result})
    @cherrypy.expose
    def filter(self,case_id):
        store = self.case.get_store(case_id)
        
        permissions_subsection = store.query_catalog( Catalog.CATALOG_APPS, 
                                "packages.available_permissions" )
        
        perm_list = []
        for perm in permissions_subsection.subsection_items:
            perm_list.append( perm.get_subvaluebyname( "name" ) )
        tmpl = self.lookup.get_template("apps_filter.html")
        return tmpl.render_unicode(case_id=case_id,permissions=perm_list)
        
    @cherrypy.expose
    def apps(self,case_id):
        '''
        Lists applications that are installed on the device. This is "case"
        page compliant
        '''
        store = self.case.get_store(case_id)
        tmpl = self.lookup.get_template("apps_home.html")
        if store == None:
            return tmpl.render_unicode(applications=None)
        else:
            return tmpl.render_unicode(case_id,applications=store.store,
                                       module=self )
    
    @cherrypy.expose
    def app(self, case_id, appname):
        tmpl = self.lookup.get_template("app.html")
        store = self.case.get_store(case_id)
        app = self._find_appbyname(store.store, appname)
        if app != None:
            timelinecont = self._get_app_timeline(store, app)
            return tmpl.render_unicode(case_id, app=app, module=self, 
                                       timelinecont=timelinecont)
        cherrypy.response.status = 404
        return tmpl.render_unicode(case_id, applications=store.store, 
                                   error="Application Not Found")
    
    @cherrypy.expose
    def strings(self, case_id, args):
        return self._handle_fileview( case_id, args, 
                                      self.htmlextract.dump_strings)
    
    @cherrypy.expose
    def hexdump(self, case_id, args ):
        return self._handle_fileview( case_id, args, self.htmlextract.dump_hex)
    
    @cherrypy.expose
    def view(self, case_id, args ):
        return self._handle_fileview(case_id, args, self.htmlextract.dump_file)
    
    @cherrypy.expose
    def getdata(self, case_id, path, table, **kw ):
        store = self.case.get_store(case_id)
        path = base64.b64decode(path).split("/")[1:]
        appname = path[0]
        app = self.find_appbyname(store.store, appname)
        if app == None:
            tmpl = self.lookup.get_template("case.html")
            cherrypy.response.status = 404
            return tmpl.render_unicode(applications=store.store,
                                       error="App Not Found")
        dbfilepath = path[1:]
        path = dbfilepath[0:len(dbfilepath)-1]
        filename = dbfilepath[len(dbfilepath)-1]
        fobj = self.get_filefrompath( store, app, path, filename)
        if fobj.ftype != ExtractStore.TYPE_MULTI:
            tmpl = self.lookup.get_template("case.html")
            cherrypy.response.status = 422
            return tmpl.render_unicode(applications=store.store,
                                       error="Bad Filetype")
        tblobj = None
        for cont in fobj.content:
            if cont.name == table:
                tblobj = cont
                break
        if tblobj == None:
            tmpl = self.lookup.get_template("case.html")
            cherrypy.response.status = 404
            return tmpl.render_unicode(applications=store.store,
                                       error="Table Not Found")
        return self._handle_tablereq(tblobj, self._parse_dtreq(kw))
    
    def _handle_fileview(self, case_id, pathtuple, handler):
        #url is encoded and also has a / at the beginning
        pathtuple = base64.b64decode(pathtuple).split("/")[1:]
        store = self.case.get_store(case_id)
        appname = pathtuple[0]
        app = self.find_appbyname(store.store, appname)
        path = pathtuple[1:len(pathtuple)-1]
        filename = pathtuple[len(pathtuple)-1]
        fobj = self.get_filefrompath( store, appname, path, filename)
        tmpl = self.lookup.get_template("fileview.html")
        if fobj != None:
            filehtml = handler(fobj)
            return tmpl.render_unicode(case_id, app=app, 
                                       path='/'+'/'.join(pathtuple[1:]),
                                       filehtml=filehtml,module=self)
        else:
            return "Error - File not found"
    
    def find_dirbyname(self, dirobj, dirnametofind):
        for d in dirobj.directories:
            if d.name == dirnametofind:
                return d
        return None
    
    def find_appbyname(self, store, appname):
        for app in store:
            if app.name == appname:
                return app
        return None
    
    def get_filefrompath(self, store, appname, path, filename):
        if type(appname) in [str,unicode]:
            app = self.find_appbyname(store.store, appname)
        else:
            app = appname
        
        """Check root path"""
        if( len(path) == 0 ):
            for f in app.directories[0].files:
                if f.name == filename:
                    return f
            return None
        
        for dirobj in app.directories:
            curdir = dirobj
            for p in path:
                founddir = self.find_dirbyname(curdir, p)
                if founddir == None:
                    break
                curdir = founddir
            if founddir != None:
                break
        
        if founddir == None:
            return None
        
        for f in founddir.files:
            if f.name == filename:
                return f
        return None
    
    def _is_empty(self, struct):
        if struct:
            return False
        else:
            return True
        
    def _column_search(self,column,searchterm):
        for name,val in column.iteritems():
            if val == None:
                continue
            if type(val) in [int,long,float,complex]:
                if searchterm in str(val):
                    return True
            elif type(val) in [str,unicode]:
                if searchterm in val:
                    return True
            else:
                print "UNKNOWN TYPE: " + str(type(val))
                if searchterm in str(val):
                    return True
        return False
    
    def _handle_tablereq(self, tablecont, params):
        cont = tablecont.content
        start = 0
        length = 10
        if "start" in params:
            start = int(params["start"])
        if "length" in params:
            length = int(params["length"])
        
        if "value" in params["search"] and len(params["search"]["value"]) != 0:
            search = params["search"]["value"]
            cont = [ row for row in cont if self._column_search(row, search) ]
        if len(cont) != 0:
            if params["order"]:
                for k,val in params["order"].iteritems():
                    colname = cont[0].keys()[int(val["column"])]
                    reversed = False
                    if val["dir"] != 'asc':
                        reversed = True
                    cont.sort(key=lambda x:x[colname],reverse=reversed)
            
        window = cont[start:(start+length)]
        
        parsed_table = []
        tblinfo = tablecont.tbl_info
        knowntable = tablecont.knowninfo
        for row in window:
            parsed_row = {}
            for colname,colval in row.iteritems():
                val = self.htmlextract._parse_column(colname, colval, tblinfo, 
                                                     knowntable, True)
                parsed_row[colname] = val
            parsed_table.append(parsed_row)
        
        response = {
            "draw": params["draw"],
            "recordsTotal": len(cont),
            "recordsFiltered": len(cont),
            "data": parsed_table
        }
        return json.dumps(response)
    
    def _parse_dtreq(self, req):
        parsed = { "columns": {}, "order": {}, "search": {} }
        for key, value in req.iteritems():
            if key.startswith("columns["):
                valgroups = re.search("columns\[(?P<index>\d)\]\[(?P<field>\w+)\]",key)
                if valgroups != None:
                    values = valgroups.groupdict()
                    if int(values["index"]) not in parsed["columns"]:
                        parsed["columns"][int(values["index"])] = {}
                    parsed["columns"][int(values["index"])][values["field"]] = value
            elif key.startswith("order["):
                values = re.search("order\[(?P<index>\d)\]\[(?P<field>\w+)\]",key).groupdict()
                if int(values["index"]) not in parsed["order"]:
                    parsed["order"][int(values["index"])] = {}
                parsed["order"][int(values["index"])][values["field"]] = value
            elif key.startswith("search["):
                values = re.search("search\[(?P<val>\w+)\]", key).groupdict()
                parsed["search"][values["val"]] = value
            else:
                parsed[key] = value
        return parsed
    
    def _find_appbyname(self, store, appname):
        for app in store:
            if app.name == appname:
                return app
        return None
    
    def _get_app_timeline(self, store, app, reverse=False):
        usage_stats = store.query_catalog( Catalog.CATALOG_LOGS, 
                                           "usage_stats.usage_stats" )
        if usage_stats == None: return None
        
        time_stats = {}
        for stat in usage_stats.subsection_items:
            name = stat.get_subvaluebyname("activity_name")
            if name.startswith(app.name) == False: continue
            time = stat.get_subvaluebyname("last_run")
            if type(time) != int:
                if time.isdigit() == False:
                    print "Non-digit timestamp??"
                    continue
                time = int(time)
            if time in time_stats:
                time_stats[time].append( name )
            else:
                time_stats[time] = [name]
        
        sorted_keys = sorted(time_stats.keys(), reverse=reverse)
        
        timeline = Timeline()
        for key in sorted_keys:
            for stat in time_stats[key]:
                timeline.add_item( TimelineItem( stat, "fa-sliders", key ) )
        
        timeline_items = timeline.get_items()
        if len(timeline_items) == 0: return None
        return timeline_items