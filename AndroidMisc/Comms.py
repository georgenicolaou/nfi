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
from IMiscSource import IMiscSource,KnownFile,ParserType,FieldType,KnownFieldSQL
from IMiscSource import Label
import ConvertUtils
from Catalog import Catalog

"""
Source: GSM 03.40

Short message transaction completed
    0000000 Short message received by the SME
    0000001 Short message forwarded by the SC to the SME but the SC is unable 
            to confirm delivery
    0000010 Short message replaced by the SC

Reserved values
    0000011..0001111 Reserved
    0010000..0011111 Values specific to each SC
Temporary error, SC still trying to transfer SM
    0100000 Congestion
    0100001 SME busy
    0100010 No response from SME
    0100011 Service rejected
    0100100 Quality of service not available
    0100101 Error in SME
    0100110..0101111 Reserved
    0110000..0111111 Values specific to each SC
Permanent error, SC is not making any more transfer attempts
    1000000 Remote procedure error
    1000001 Incompatible destination
    1000010 Connection rejected by SME
    1000011 Not obtainable
    1000100 Quality of service not available
    1000101 No interworking available
    1000110 SM Validity Period Expired
    1000111 SM Deleted by originating SME
    1001000 SM Deleted by SC Administration
    1001001 SM does not exist (The SM may have previously existed in the SC 
                                but the SC no longer has knowledge of it or 
                                the SM may never have previously existed in the 
                                SC)
    1001010..1001111 Reserved
    1010000..1011111 Values specific to each SC

Temporary error, SC is not making any more transfer attempts
    1100000 Congestion
    1100001 SME busy
    1100010 No response from SME
    1100011 Service rejected
    1100100 Quality of service not available
    1100101 Error in SME
    1100110..1101001 Reserved
    1101010..1101111 Reserved
    1110000..1111111 Values specific to each SC bits value/usage

7 1 Bits 0..6 reserved
"""
TP_STATUS = {
    -1: "OK", # Android specific value
    0: "Received",
    1: "Unconfirmed",
    2: "Replaced",
    
    #Temporary Errors
    0x20: "SC Congestion",
    0x21: "SME Busy",
    0x22: "No Response from SME",
    0x23: "Service Rejected",
    0x24: "QoS N/A",
    0x25: "SME Error",
    
    #Permanent Errors
    0x40: "RPC Error",
    0x41: "Incompatible Destination",
    0x42: "Connection Rejected by SME",
    0x43: "Not Obtainable",
    0x44: "QoS N/A",
    0x45: "No interworking available",
    0x46: "SM Validity Period Expired",
    0x47: "SM Deleted by originating SME",
    0x48: "SM Deleted by SC Admin",
    0x49: "SM Does not exist",
    
    #Termp error , no more transfer attempts
    0x60: "Congestion",
    0x61: "SME Busy",
    0x62: "No response from SME",
    0x63: "Service Rejected",
    0x64: "QoS N/A",
    0x65: "Error in SME"
}
def SMS_TP_Status2text(status):
    if status in TP_STATUS:
        return TP_STATUS[status]
    return "Unknown"

def sendDateParse(date):
    if date == 0:
        return "N/A"
    return ConvertUtils.JsToUnix(date)

CALL_TYPES = {
    1: "Incoming",
    2: "Outgoing",
    3: "Missed"
}
def callTypeToStr(ctype):
    if ctype in CALL_TYPES:
        return CALL_TYPES[ctype]
    return "Unknown"
        
class Calls(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_COMMS
    title = Label( "Telephony", "telephony" )
    relative_directories = [ "data", "com.android.providers.contacts", 
                            "databases"]
    knownfiles = {
        "contacts2.db": KnownFile(ParserType.TYPE_SQLITE3, 
            {
                Label("Calls", "calls") : [
                    KnownFieldSQL(
                        FieldType.TYPE_ARRAY,
                        """SELECT * FROM calls""",
                        contents= [
                            KnownFieldSQL( FieldType.TYPE_DATE, None, "Date", 
                                    "date", converter=ConvertUtils.JsToUnix ),
                            KnownFieldSQL( FieldType.TYPE_INT, None, "Type", 
                                           "type", converter=callTypeToStr),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Number", 
                                           "number" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Contact", 
                                           "name" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                           "Duration (seconds)", "duration" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                           "Number Geolocation", 
                                           "geocoded_location" ),
                        ]
                    )
                ]
            }
        )
    }
    
class SmsMms(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_COMMS
    title = Label( "Telephony", "telephony" )
    relative_directories = [ "data", "com.android.providers.telephony", 
                            "databases" ]
    knownfiles = {
        "mmssms.db": KnownFile(ParserType.TYPE_SQLITE3,
            {
                Label("SMS Messages", "sms_messages") : [
                    KnownFieldSQL( 
                        FieldType.TYPE_ARRAY,
                        """SELECT * FROM sms""",
                        contents= [
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                           "Message ID", "_id" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Status", 
                                           "status", 
                                           converter=SMS_TP_Status2text ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Type", 
                                           "type", 
                                           converter=lambda val: "Outgoing" if val == 2 else "Incoming" ),
                            KnownFieldSQL( FieldType.TYPE_DATE, None, 
                                           "Date Send", "date_sent", 
                                           converter=sendDateParse ),
                            KnownFieldSQL( FieldType.TYPE_DATE, None, 
                                           "Local Date", "date", 
                                           converter=ConvertUtils.JsToUnix ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                           "From/To", "address" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Seen", 
                                           "seen", converter=lambda val: "Yes" if val == 1 else "No" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Message", 
                                           "body" ),
                        ]
                    ),
                ],
            }
        )
    }