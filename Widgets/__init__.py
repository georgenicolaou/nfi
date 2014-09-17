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
import os
from copy import copy
from mako.lookup import TemplateLookup
from ModuleImporter import Importer
from IWidget import IWidget

PIE_CHART = 1
TIMEGRAPH = 2
TABLE = 3

_WIDGET_PATH = os.path.join( "_html", "widgets" )

_TEMPL = TemplateLookup(directories=_WIDGET_PATH, output_encoding='utf-8', 
                            encoding_errors='ignore')
_MODULES = Importer().get_package_modules_dict( "Widgets", IWidget(), 
                                                'module_id' )
_ID = 1

def _get_id():
    global _ID
    ret = _ID
    _ID += 1
    return ret

def render_widget( widget_id, colsize, data, title ):
    global _MODULES, _TEMPL
    if widget_id in _MODULES:
        res = _MODULES[widget_id]._render_widget( _get_id(), _TEMPL, colsize, 
                                                  title, data )
    else:
        return None
    return res

def render_widget_object(widget):
    return widget._render( _get_id(), _TEMPL )

def get_widget(widget_id):
    if widget_id in _MODULES:
        return type(_MODULES[widget_id])()
    return None
    