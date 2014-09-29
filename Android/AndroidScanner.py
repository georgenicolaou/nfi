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
import os,traceback

from IScanner import IScanner
from ApplicationParser import ApplicationParser
from MiscParser import MiscParser
from ExtractStore import ExtractStore
from AndroidAuxiliary.ApplicationMiscParser import ApplicationMiscParser
from AndroidAuxiliary.PermissionsJoiner import PermissionsJoiner
from ModuleImporter import Importer
from IAuxiliary import IAuxiliary
from MountPoints import MountPoints
from AndroidDeviceVersion import AndroidDeviceVersion
class AndroidScanner(IScanner):
    
    def begin_scan(self,location):
        try:
            self._begin_scan(location)
        except:
            self.print_queue.put("**ERROR**:")
            traceback.print_exc()
            self.print_queue.put(traceback.format_exc())
            self.print_queue.put("FINERR")
        
    #Missing variables are initialized in IScanner
    def _begin_scan(self, location):
        #----------------------------------------------------------------------
        #Initiating device version scanning
        #----------------------------------------------------------------------
        #XXX should remove this and add it in HttpServe when loading case
        self.print_queue.put("** Determining Device/Apps versions **")
        mounts = MountPoints()
        mounts.set_mountpoint(MountPoints.MOUNT_DATA, location)
        versions = AndroidDeviceVersion(self.print_queue,mounts)
        versions.populate_info()
        versions.print_debug()
        
        
        #----------------------------------------------------------------------
        #Initiating file system scanning and populating of data
        #----------------------------------------------------------------------
        self.print_queue.put("** Running Application Parser **")
        app_parser = ApplicationParser( self.print_queue, self.extract_store, 
                                        location, settings=self.settings, 
                                        versions=versions )
        #XXX note that this is hard-coded. If for some reason Android app store
        # location changes, this would need to reflect it
        app_parser.scan_directory( os.path.join( location, "data" ) )
        
        self.print_queue.put("** Running Configuration Parser **")
        misc_parser = MiscParser( self.print_queue, self.extract_store, 
                                  settings=self.settings, versions=versions )
        misc_parser.scan_directory(location)
        #----------------------------------------------------------------------
        # Initiating auxiliary modules
        #----------------------------------------------------------------------
        self.print_queue.put("** Running Auxiliary Modules **")
        
        auxmods = Importer().get_package_modules( "AndroidAuxiliary", 
                        IAuxiliary(), ( self.extract_store, self.print_queue ) )
        auxmods.sort(key=lambda d: d.index)
        for mod in auxmods:
            mod.begin()
        #Finished, sending FIN signal
        self.print_queue.put("FIN")
        return