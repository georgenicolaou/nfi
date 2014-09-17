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
import datetime

def WebkitToUnix( timestamp ):
    if type(timestamp) != int:
        try:
            timestamp = int(timestamp)
        except:
            return timestamp
    if timestamp == None or timestamp == 0:
        return timestamp
    return timestamp / 1000000 - 11644473600    

def JsToUnix( timestamp ):
    if timestamp == None:
        return timestamp
    return int(timestamp) / 1000

def UnixTimestamp( timestamp ):
    return timestamp

def HexToUnix( timestamp ):
    mstimestamp = int(timestamp,16)
    return mstimestamp / 1000

def BintoASCII( buf ):
    return buf.encode("hex")