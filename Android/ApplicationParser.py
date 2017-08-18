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
from IApp import IApp
from MimeGuesser import MimeGuesser
import ExtractStore
import os
from os import listdir
from os.path import isfile, isdir, islink, join, basename, dirname
from MiscUtils import genfilesig, DEFAULT_HASHER
from ModuleImporter import Importer

class ApplicationParser(object):
    
    parser_name = "Android Application Parser"
    appstore = {}
    exstore = None        
    def __init__(self, outqueue=None, extract_store=None, mountpoint=None, 
                 settings=None, versions=None ):
        self.mimguess = MimeGuesser()
        self.outqueue = outqueue
        self.settings = settings
        self.versions = versions
        imp = Importer()
        app_modules = imp.get_package_modules("AndroidApps", IApp())
        for app in app_modules:
            name = app.get_packagename()
            if name in self.appstore:
                self.appstore[name].append(app)
            else:
                self.appstore[name] = [app]
        if extract_store != None:
            self.exstore = extract_store
        else:
            self.exstore = ExtractStore.ExtractStore()
           
    def get_extractedstore(self):
            return self.exstore
        
    def get_package_list(self):
        return self.appstore.keys()
    
    def get_package(self, name):
        if name not in self.appstore:
            return None
        if len(self.appstore[name]) == 1:
            if self.appstore[name][0].has_defaultversion() == False:
                self.outqueue.put("Package {} is not default".format(name))
            return self.appstore[name][0]
        
        """
        If multiple entries for the same package exist, then we need to decide
        which one we should use
        """
        default = None
        appversion = self.versions.get_application_version(name)
        if appversion == None or appversion == "N/A":
            self.outqueue.put("{} could not determine App version".format(name))
        else:
            try:
                appversion = int(appversion)
            except:
                pass
        for defn in self.appstore[name]:
            if defn.has_defaultversion:
                if default != None: 
                    self.outqueue.put("{} has more than one default".format(name))
                default = defn
            if defn.has_version(appversion):
                return defn
        return default
    
    def handle_file(self, filename, dirpath, app):
        filepath = join(dirpath,filename)
        handler = self.mimguess.get_handler(filepath)
        knowninfo = app.get_file_info(filename)
        fobject = None
        if handler != None:
            fobject = handler(filename,filepath,knowninfo,self.outqueue,
                              self.settings)
        else:
            """
            This is a remote case where no handler can handle the file.
            However, the default handler for unknown files should always be the
            raw data handler
            """
            fobject = ExtractStore.ApplicationFile(filename,
                                                   ExtractStore.TYPE_NONE)
        fobject.set_mime(self.mimguess.get_filemime(filepath))
        fobject.add_sig(genfilesig(filepath, DEFAULT_HASHER))
        fobject.add_stats(os.stat(filepath))
        return fobject
        
        
    
    def scan_single_app_dir(self, dirroot, app, dirobject, store_app):
        for f in listdir(dirroot):
            filepath = join(dirroot,f)
            if isdir(filepath): 
                subdirobject = dirobject.add_dir(f)
                self.scan_single_app_dir(filepath, app, subdirobject, store_app)
            elif islink(filepath):
                """Skip for now"""
                continue
            elif isfile(filepath):
                try:
                    dirobject.add_file(self.handle_file(f, dirroot, app))
                    store_app.totalfiles += 1
                except:
                    print("Error handling file %(fname)s" % {'fname': join(dirroot,f)})
        return
    
    
    def read_link(self, linkpath):
        target_path = os.readlink(linkpath)
        if os.path.isabs(target_path):
            return target_path
        return join(dirname(linkpath),target_path)
    
    def scan_single_app(self, approot_path, app):
        #print "[APP]: " + app.get_packagename()
        if self.outqueue != None:
            self.outqueue.put("[APP]: " + app.get_packagename())
        store_app = self.exstore.create_application(
                                app.get_packagename(), app.get_canonicalname())
        rootdir = store_app.add_directory(approot_path)
        store_app.add_root_stats( os.stat(approot_path) )
        for f in listdir(approot_path):
            filepath = join(approot_path,f)
            if isdir(filepath):
                dirobject = rootdir.add_dir(f)
                self.scan_single_app_dir(filepath, app, dirobject, store_app)
            elif islink(filepath):
                if filepath.endswith("lib"):
                    store_app.set_library_path(self.read_link(filepath))
            elif isfile(filepath):
                store_app.totalfiles += 1
                rootdir.add_file(self.handle_file(f,approot_path,app))
        return
    
    def scan_directory(self, root):
        for dfile in os.listdir(root):
            fqname = join(root,dfile)
            if isdir( fqname ):
                app = self.get_package( dfile )
                if app == None:
                    app = IApp()
                    app.set_packagename( dfile )
                self.scan_single_app( fqname, app )
            else:
                print "Stray file found: " + fqname
                #self.handle_file(fqname, None)
        if self.outqueue != None:
            self.outqueue.put("Scanned Total Apps: " + str(len(self.exstore.store)) )
                
        