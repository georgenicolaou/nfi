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
from IMiscSource import IMiscSource, ParserType
from ParseHandlers import *
from ModuleImporter import Importer

import ExtractStore
import os,re

"""
The MiscParser is responsible for 
"""
class MiscParser(object):

    parser_name = "Catalog Parser (MiscParser)"
    print_queue = None
    store = None
    misc_definitions = None
    sub_parsers = {
        ParserType.TYPE_XML: parse_xml,
        ParserType.TYPE_REGEX: parse_regex,
        ParserType.TYPE_BINARY: parse_binary,
        ParserType.TYPE_SQLITE3: parse_sqlite
    }
    
    def __init__(self, print_queue=None,store=None, settings=None):
        '''
        Initialize the print_queue and specify a store if one is needed. If not 
        then the class automatically  creates a new instance
        '''
        self.print_queue = print_queue
        if store == None:
            self.store = ExtractStore.ExtractStore()
        else:
            self.store = store
        imp = Importer()
        self.misc_definitions = imp.get_package_modules( "AndroidMisc", 
                                                              IMiscSource() )
        if self.print_queue != None:
            self.print_queue.put("[MiscParser]: Initialized Misc Parser")
        self.dummyRE = type(re.compile("A"))
        self.settings = settings
        return
    
    def get_package_list(self):
        lst = []
        for module in self.misc_definitions:
            lst.append(module.title.label)
        return lst
    
    def _filter_defn(self, defn, directory_name, depth):
        '''Filters out known file paths that do not match this path'''
        new_defn = []
        for known_definition in defn:
            known_dir = known_definition.get_relative_dir( depth )
            if type(known_dir) == str:
                if known_dir == directory_name:
                    new_defn.append(known_definition)
            elif type(known_dir) == self.dummyRE:
                if known_dir.match(directory_name) != None:
                    new_defn.append(known_definition)
        return new_defn
    
    def get_handler(self, known_file):
        if known_file.parser in self.sub_parsers.keys():
            return self.sub_parsers[known_file.parser]
        return None
    
    def scan_misc(self, known_defn, scan_dir ):
        '''
        Scan all files within the known files definitions and generate a new
        section containing the extracted info.
        '''
        self.print_queue.put( "[MISC] Scanning " + known_defn.title.label )
        catalog = self.store.get_misccatalog( known_defn.catalog_id )
        
        for files_defn,known_file in known_defn.knownfiles.iteritems():
            handler = self.get_handler(known_file)
            if handler != None:
                if type(files_defn) == str:
                    files_defn = [files_defn]
                for file_name in files_defn:
                    if type(file_name) == self.dummyRE:
                        for dir_file in os.listdir(scan_dir):
                            full_dirfile = os.path.join( scan_dir, dir_file )
                            if os.path.isfile( full_dirfile ):
                                if file_name.match( full_dirfile ) != None:
                                    subsections = handler( dir_file, 
                                        full_dirfile, known_file, 
                                        self.print_queue, self.settings )
                                    if subsections != None:
                                        section = catalog.get_section( 
                                                    known_defn.title, True )
                                        section.add_subsections( subsections )
                        continue
                    else:
                        file_path = os.path.join( scan_dir, file_name )
                        if os.path.exists(file_path):
                            subsections = handler(file_name, file_path, 
                                                   known_file, self.print_queue)
                            if subsections != None:
                                section = catalog.get_section( known_defn.title, 
                                                               True )
                                section.add_subsections( subsections )
        
        #catalog.add_section( section )
        
    def scan_directory(self, root, depth=0, defn=None):
        '''
        Recursively scans the 'root' directory for matching known file paths
        '''
        if defn == None:
            defn = self.misc_definitions
        for foundfile in os.listdir(root):
            joined_path = os.path.join( root, foundfile)
            if os.path.isdir(joined_path) == True:
                filtered_defn = self._filter_defn(defn, foundfile, depth)
                if len(filtered_defn) != 0:
                    left_defn = [] 
                    for known_defn in filtered_defn:
                        if known_defn.get_max_depth() == depth+1:
                            self.scan_misc( known_defn, joined_path )
                        else:
                            left_defn.append( known_defn )
                    self.scan_directory( joined_path, depth+1, left_defn )
            
            