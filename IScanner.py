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

from ExtractStore import ExtractStore

class IScanner(object):

    def __init__(self, print_queue=None, store=None, settings=None):
        if store != None:
            self.extract_store = store
        else:
            self.extract_store = ExtractStore()
        if print_queue != None:
            self.print_queue = print_queue
        else:
            self.print_queue = Queue()
            printer = Thread(target=self._stdoutprinter, args=(self.print_queue,))
            printer.start()
        self.settings = settings
            
    
    def _stdoutprinter(self, queue):
        while True:
            try:
                res = queue.get()
                print res
            except KeyboardInterrupt:
                break
        return

    def get_extractedstore(self):
        return self.extract_store
    
    def begin_scan(self,location):
        print "Overload Me"