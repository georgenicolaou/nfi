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
from IMiscSource import IMiscSource,KnownFile,ParserType,FieldType,KnownField,KnownFieldXML,ReadTypeXML
from IMiscSource import Label
import ConvertUtils
from Catalog import Catalog

STR_PLATFORM_VERSION = "Platform Version"
STR_AVAILABLE_PERMISSIONS = "Available Permissions"
STR_INSTALLED_APPLICATIONS = "Installed Applications"

#/frameworks/base/core/java/android/content/pm/PermissionInfo.java:28
ANDROID_PROTECTIONS_BASE = {
    0 : "NORMAL",
    1 : "DANGEROUS",
    2 : "SIGNATURE",
    3 : "SIGNATURE_OR_SYSTEM"
}

ANDROID_PROTECTIONS_FLAGS = {
    0 : "",
    0x10 : "SYSTEM",
    0x20 : "DEVELOPMENT",
    0x30 : "SYSTEM + DEVELOPMENT"
}

def protectionToFlags(val):
    if val.isdigit() == False: return val
    try: val = int(val)
    except: return val
    
    base = val & 0x0f
    flag = val & 0xf0
    
    if flag in ANDROID_PROTECTIONS_FLAGS:
        flagstr = ANDROID_PROTECTIONS_FLAGS[flag]
        if flag != 0:
            flagstr += " + "
    else:
        flagstr = str(flag)
    if base in ANDROID_PROTECTIONS_BASE:
        basestr = ANDROID_PROTECTIONS_BASE[base]
    else:
        basestr = str(base)
    return "{}{}".format( flagstr, basestr )

class Packages(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_APPS
    title = Label( "Packages & Permissions", "packages" )
    relative_directories = [ "system" ]
    knownfiles = {
        "packages.xml": KnownFile(ParserType.TYPE_XML,
            {
                Label(STR_INSTALLED_APPLICATIONS, "installed_apps") : [ #XXX add signatures as well?
                    KnownFieldXML( 
                        FieldType.TYPE_ARRAY, 
                        ["./package", "./updated-package", "./shared-user"],
                        "applications",
                        contents = [
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".",
                                "name",
                                "Package Name",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "name" 
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "codePath",
                                "APK Path",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "codePath"
                            ),
                            #Flags information can be found under
                            #/frameworks/base/core/java/android/content/pm/ApplicationInfo.java:34
                            KnownFieldXML(
                                FieldType.TYPE_INT,
                                ".",
                                "flags",
                                "Flags",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "flags"
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_DATE,
                                ".",
                                "ft",
                                "First Install Time",
                                read_type= ReadTypeXML.READ_ATTR,
                                attr= "ft",
                                converter= ConvertUtils.HexToUnix
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_DATE,
                                ".",
                                "it",
                                "Install Time",
                                read_type= ReadTypeXML.READ_ATTR,
                                attr= "it",
                                converter= ConvertUtils.HexToUnix
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_DATE,
                                ".",
                                "ut",
                                "Update Time",
                                read_type= ReadTypeXML.READ_ATTR,
                                attr= "ut",
                                converter= ConvertUtils.HexToUnix
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "version",
                                "Version",
                                read_type= ReadTypeXML.READ_ATTR,
                                attr= "version",
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "userId",
                                "User ID",
                                read_type= ReadTypeXML.READ_ATTR,
                                attr= "userId",
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "installer",
                                "Installer",
                                read_type= ReadTypeXML.READ_ATTR,
                                attr= "installer",
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_CONTAINER,
                                "./perms",
                                "permissions",
                                "Permissions",
                                contents= [
                                    KnownFieldXML(
                                        FieldType.TYPE_STR,
                                        ".",
                                        "name",
                                        "Permission",
                                        read_type=ReadTypeXML.READ_ATTR,
                                        attr="name"
                                    )
                                ]
                            )
                        ]
                    )
                ],
                Label(STR_AVAILABLE_PERMISSIONS, "available_permissions") : [
                    KnownFieldXML( 
                        FieldType.TYPE_CONTAINER,
                        "./permissions",
                        "available_permissions",
                        contents = [
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "name",
                                "Name",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr="name"
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "package",
                                "Package",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr="package"
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_STR,
                                ".",
                                "protection",
                                "Protection",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr="protection",
                                converter=protectionToFlags
                            )
                        ] 
                    )
                ],
                Label(STR_PLATFORM_VERSION, "platform_version") : [
                    KnownFieldXML( 
                        FieldType.TYPE_STR, 
                        "./last-platform-version",
                        "platform_version", 
                        "Platform Version", 
                        read_type = ReadTypeXML.READ_ATTR, 
                        attr="internal" 
                    ),
                ]
            }
        )
    }