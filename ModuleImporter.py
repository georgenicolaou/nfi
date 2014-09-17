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
from pkgutil import *
from importlib import import_module
import inspect

class Importer(object):
    def __init__(self):
        return
    
    def get_package_modules_dict(self, package_name, parent_obj, keyfield, 
                                 args=None ):
        return self._load_dict( [package_name], package_name + u".", parent_obj, 
                                keyfield, args)
        
    def get_package_modules(self, package_name, parent_obj, args=None ):
        return self._load( [package_name], package_name + u".", parent_obj, 
                           True, args )
    
    def get_package_modules_list(self, package_name, parent_obj ):
        return self._load( [package_name], package_name + u".", parent_obj )
    
    def _load(self, path, prefix, parent_obj, instantiate=False, args=None ):
        modules = []
        for _, name, is_package in walk_packages( path, prefix=prefix ):
            if is_package: continue
            module = import_module( name )
            for member in dir(module):
                if member == parent_obj.__class__.__name__: continue
                member_obj = getattr( module, member )
                if inspect.isclass( member_obj ) == False: continue
                if issubclass( member_obj, parent_obj.__class__ ):
                    if instantiate:
                        if args != None: obj = member_obj(*args)
                        else: obj = member_obj()
                        modules.append( obj )
                    else:
                        modules.append( member )
        return modules
    
    def _load_dict(self, path, prefix, parent_obj, keyfield, args=None ):
        modules = {}
        for _, name, is_package in walk_packages( path, prefix=prefix ):
            if is_package: continue
            module = import_module( name )
            for member in dir(module):
                if member == parent_obj.__class__.__name__: continue
                member_obj = getattr( module, member )
                if inspect.isclass( member_obj ) == False: continue
                if issubclass( member_obj, parent_obj.__class__ ):
                    if args != None: tmpobj = member_obj(*args)
                    else: tmpobj = member_obj()
                    modules[getattr( tmpobj, keyfield )] = tmpobj
        return modules