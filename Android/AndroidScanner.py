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
from multiprocessing import Queue
from threading import Thread
import os

from IScanner import IScanner
from ApplicationParser import ApplicationParser
from MiscParser import MiscParser
from ExtractStore import ExtractStore
from AndroidAuxiliary.ApplicationMiscParser import ApplicationMiscParser
from AndroidAuxiliary.PermissionsJoiner import PermissionsJoiner
from ModuleImporter import Importer
from IAuxiliary import IAuxiliary
class AndroidScanner(IScanner):
    
    #Missing variables are initialized in IScanner
    def begin_scan(self, location):
        #----------------------------------------------------------------------
        #Initiating file system scanning and populating of data
        #----------------------------------------------------------------------
        self.print_queue.put("** Running Application Parser **")
        app_parser = ApplicationParser( self.print_queue, self.extract_store, 
                                        location, settings=self.settings )
        #XXX note that this is hard-coded. If for some reason Android app store
        # location changes, this would need to reflect it
        app_parser.scan_directory( os.path.join( location, "data" ) )
        
        self.print_queue.put("** Running Configuration Parser **")
        misc_parser = MiscParser( self.print_queue, self.extract_store, 
                                  settings=self.settings )
        misc_parser.scan_directory(location)
        #----------------------------------------------------------------------
        # Initiating auxiliary modules
        #----------------------------------------------------------------------
        self.print_queue.put("** Running Auxiliary Modules **")
        
        auxmods = Importer().get_package_modules( "AndroidAuxiliary", 
                        IAuxiliary(), ( self.extract_store, self.print_queue ) )
        
        for mod in auxmods:
            mod.begin()
        #Finished, sending FIN signal
        self.print_queue.put("FIN")
        return