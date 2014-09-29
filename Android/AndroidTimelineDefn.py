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
from TimelineDefn import TimelineDefn, TimelineTitle, DataQueryCatalog
from TimelineDefn import TimelineMessage
from TimelinePlugins.TimelineBox import TimelineBox, BoxType
from Catalog import Catalog

timeline = [
    TimelineDefn( 
        TimelineTitle( "Call", "fa-phone"), 
        DataQueryCatalog( 
            Catalog.CATALOG_COMMS, 
            "telephony.calls",
            "date", "type", "name", "number", "duration" 
        ), 
        "date", 
        [
            TimelineMessage(u"{} call from {} ({})", "type","name", "number"),
            TimelineMessage(u"Duration: {}", "duration")
        ] 
    ),
    TimelineDefn( 
        TimelineTitle( "SMS", "fa-comment"), 
        DataQueryCatalog( 
            Catalog.CATALOG_COMMS, 
            "telephony.sms_messages",
            "date", "date_send", "status", "type", "address", "seen", "body" 
        ), 
        "date", 
        [
            TimelineMessage(u"{} SMS Message from/to {}", "type","address" ),
            TimelineMessage(u"Message Status: {}", "status"),
            TimelineMessage(u"Content:")
        ],
        [TimelineBox( BoxType.TYPE_TEXTBOX, None, u"{}", "body")]
    ),
    TimelineDefn(
        TimelineTitle( "Website Visit", "fa-globe"),
        DataQueryCatalog( Catalog.CATALOG_NETWORKING, 
                          "internet_browsing.browser_history", "date", 
                          "duration", "title", "url" ),
        "date",
        [
            TimelineMessage(u"Visited Website: {}", "title"),
            TimelineMessage(u"Duration: {}", "duration"),
            TimelineMessage(u"URL:")
         ],
        [TimelineBox(BoxType.TYPE_TEXTBOX, None, u"{}", "url")]
                 
    ),
    TimelineDefn(
        TimelineTitle( "Activity Executed", "fa-sliders"),
        DataQueryCatalog( Catalog.CATALOG_LOGS, "usage_stats.usage_stats", 
                          "activity_name", "last_run" ),
        "last_run",
        [TimelineMessage( u"Activity:{}", "activity_name")]
    ),
    TimelineDefn( 
        TimelineTitle( "Facebook Message Arrived", "fa-facebook"), 
        DataQueryCatalog( 
            Catalog.CATALOG_COMMS, 
            "internet_chats.facebook_messenger_chats",
            "date", "sender", "type", "text" 
        ), 
        "date", 
        [
            TimelineMessage(u"{} Facebook message send by <b>{}</b> and reads:",
                            "type","sender")
        ],
        [TimelineBox( BoxType.TYPE_TEXTBOX, None, u"{}", "text" )] 
    ),
    TimelineDefn(
        TimelineTitle( "LinkedIn Message Arrived", "fa-linkedin" ),
        DataQueryCatalog( Catalog.CATALOG_COMMS, 
                          "internet_chats.linkedin_messages", "date", "from", 
                          "subject", "partial_message"),
        "date",
        [
         TimelineMessage(u"From: {}", "from"),
         TimelineMessage(u"Subject: {}", "subject"),
         TimelineMessage(u"Partial Contents:")
        ],
        [TimelineBox(BoxType.TYPE_TEXTBOX, None, u"{}", "partial_message")]
    ),
    TimelineDefn(
        TimelineTitle( "Skype", "fa-skype" ),
        DataQueryCatalog( Catalog.CATALOG_COMMS, 
                          "internet_chats.skype_messages", "account", "date", 
                          "type", "status", "from", "message" ),
        "date",
        [
         TimelineMessage(u"Account: {}", "account"),
         TimelineMessage(u"Type: {}", "type"),
         TimelineMessage(u"Status: {}", "status"),
         TimelineMessage(u"From: {}", "from"),
         TimelineMessage(u"Contents:")
        ],
        [TimelineBox(BoxType.TYPE_TEXTBOX, None, u"{}", "message")]
        
    )
]