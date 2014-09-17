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
import hashlib

DEFAULT_HASHER = hashlib.sha256()

def genfilesig(filepath,hasher=DEFAULT_HASHER,bs=65536):
        try:
            f = open(filepath,"rb")
            while True:
                buf = f.read(bs)
                if not buf:
                    break
                hasher.update(buf)
            f.close()
            return hasher.hexdigest()
        except:
            print "Error opening file:" + filepath
            return None