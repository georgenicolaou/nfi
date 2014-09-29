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
from IDeviceVersion import IDeviceVersion
from MountPoints import MountPoints
from AndroidMisc.Packages import Packages
import ExtractStore
import ParseHandlers

import os
class AndroidDeviceVersion(IDeviceVersion):
    name = "AndroidDeviceVersion"
        
    def read_platform_version(self, sub):
        if len(sub.subsection_items) == 0:
            self.selfprint("Version subsection is empty")
            return False
        
        version_item = sub.subsection_items[0]
        if version_item.item_name != "platform_version":
            self.selfprint("Version subsection item is not platform version")
            return False
        
        version = version_item.item_value
        if "isdigit" in dir(version):
            if version.isdigit():
                self.device_version = int(version)
        else:
            self.device_version = version
        
        return True
    
    def read_app_versions(self, sub):
        if len(sub.subsection_items) == 0:
            self.selfprint("No applications found")
            return False
        
        for appinfo in sub.subsection_items:
            if appinfo.item_type != ExtractStore.TYPE_MULTI:
                self.selfprint("Appinfo item is not TYPE_MULTY")
                continue
            package_name = appinfo.get_subvaluebyname("name")
            if package_name == None:
                self.selfprint("App with no name?")
                continue
            app_version = appinfo.get_subvaluebyname("version")
            if 'isdigit' in dir(app_version):
                if app_version.isdigit():
                    app_version = int(app_version)
            if package_name in self.application_versions:
                self.selfprint("Conflicting app versions for " + package_name)
            self.application_versions[package_name] = app_version
        return True
    
    def populate_info(self):
        self.selfprint("Initializing version detection")
        data_location = self.mounts.get_mountpoint(MountPoints.MOUNT_DATA)
        
        packagesxml = os.path.join( data_location, "system", "packages.xml" )
        if os.path.exists(packagesxml) == False:
            self.selfprint("Unable to locate packages.xml")
            return False
        
        """
        We are using AndroidMisc.Packages since it covers what we need. It is
        a bit of a hack but we can live with it. Also if any changes to the
        packages.xml file take place we can just clone and modify those changes
        """
        self.selfprint("Parsing packages.xml")
        subsections = ParseHandlers.parse_xml( "packages.xml", packagesxml, 
                        Packages.knownfiles["packages.xml"], self.print_queue )
        
        
        for sub in subsections:
            if sub.subsection_name == "platform_version":
                self.selfprint("Reading platform version")
                self.read_platform_version(sub)
                continue
            elif sub.subsection_name == "installed_apps":
                self.selfprint("Reading application versions")
                self.read_app_versions(sub)
        
        self.selfprint("Finished")
        
        return True
        