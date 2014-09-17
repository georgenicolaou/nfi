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


def deleted2Text(val):
    if val == 0:
        return "No"
    else:
        return "Yes"

NUMBER_TYPES = {
    19: "Assistant",
    8: "Callback",
    9: "Car",
    10: "Company Main",
    5: "Home Fax",
    4: "Work Fax",
    1: "Home",
    11: "ISDN",
    12: "Main",
    20: "MMS",
    2: "Mobile",
    7: "Other",
    13: "Other Fax",
    6: "Pager",
    14: "Radio",
    15: "Telex",
    16: "TTY TDD",
    3: "Work",
    17: "Work Mobile",
    18: "Work Pager"
}
def phoneType2Text(val):
    try:
        val = int(val)
        if val in NUMBER_TYPES:
            return NUMBER_TYPES[val]
    except:
        pass
    return "Unknown"

class Contacts(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_COMMS
    title = Label( "Contacts", "contacts" )
    relative_directories = [ "data", "com.android.providers.contacts", 
                            "databases"]
    knownfiles = {
        "contacts2.db": KnownFile(ParserType.TYPE_SQLITE3, 
            {
                Label("Contacts", "contacts") : [
                    KnownFieldSQL(
                        FieldType.TYPE_ARRAY,
                        """
                         SELECT DISTINCT 
                            data._id                         AS _id,
                            data.raw_contact_id              AS person,
                            data.is_primary                  AS isprimary,
                            data.data1                       AS number,
                            data.data2                       AS num_type,
                            data.data3                       AS label,
                            data.data1                       AS number_key,
                            name.data1                       AS name,
                            raw_contacts.display_name        AS display_name,
                            note.data1                       AS notes,
                            view_v1_people.account_name,
                            view_v1_people.account_type,
                            raw_contacts.times_contacted     AS times_contacted,
                            raw_contacts.last_time_contacted AS last_time_contacted,
                            raw_contacts.custom_ringtone     AS custom_ringtone,
                            raw_contacts.send_to_voicemail   AS send_to_voicemail,
                            raw_contacts.starred             AS starred,
                            raw_contacts.deleted             AS deleted,
                            organization._id                 AS primary_organization,
                            email._id                        AS primary_email,
                            phone._id                        AS primary_phone,
                            phone.data1                      AS pnumber,
                            phone.data2                      AS ptype,
                            phone.data3                      AS plabel,
                            phone.data1                      AS pnumber_key
                        FROM   data
                           JOIN phone_lookup
                             ON ( data._id = phone_lookup.data_id )
                           JOIN mimetypes
                             ON ( mimetypes._id = data.mimetype_id )
                           JOIN raw_contacts
                             ON ( raw_contacts._id = data.raw_contact_id )
                           JOIN view_v1_people
                             ON ( raw_contacts._id = view_v1_people._id )
                           LEFT OUTER JOIN data name
                             ON ( raw_contacts._id = name.raw_contact_id
                                 AND (
                                  SELECT mimetype
                                      FROM   mimetypes
                                      WHERE  mimetypes._id = name.mimetype_id
                                 ) = 'vnd.android.cursor.item/name' )
                           LEFT OUTER JOIN data organization
                             ON ( raw_contacts._id = organization.raw_contact_id
                                AND (
                                  SELECT mimetype
                                   FROM   mimetypes
                                   WHERE  mimetypes._id = 
                                       organization.mimetype_id
                                 ) = 'vnd.android.cursor.item/organization'
                                AND organization.is_primary )
                           LEFT OUTER JOIN data email
                            ON ( raw_contacts._id = email.raw_contact_id
                                 AND
                                   (
                                       SELECT mimetype
                                        FROM   mimetypes
                                        WHERE  mimetypes._id =
                                       email.mimetype_id
                                    ) = 'vnd.android.cursor.item/email_v2'
                                AND email.is_primary )
                           LEFT OUTER JOIN data note
                            ON ( raw_contacts._id = note.raw_contact_id
                             AND (
                                 SELECT mimetype
                                  FROM   mimetypes
                                  WHERE  mimetypes._id = note.mimetype_id
                             ) = 'vnd.android.cursor.item/note' )
                        LEFT OUTER JOIN data phone
                            ON ( raw_contacts._id = phone.raw_contact_id
                            AND (
                                SELECT mimetype
                                 FROM   mimetypes
                                 WHERE  mimetypes._id =
                                phone.mimetype_id
                            ) = 'vnd.android.cursor.item/phone_v2'
                            AND phone.is_primary )
                        WHERE  
                            mimetypes.mimetype = 'vnd.android.cursor.item/phone_v2'  
                        """,
                        contents= [
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Person ID", "person" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Name", "name" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Number", "number" ),
                            KnownFieldSQL( FieldType.TYPE_INT, None, 
                                    "Type", "num_type", converter=phoneType2Text ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Label", "label" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Times Contacted", "times_contacted" ),
                            KnownFieldSQL( FieldType.TYPE_DATE, None, 
                                    "Last Contact Date", "last_time_contacted", 
                                    converter=ConvertUtils.JsToUnix ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Notes", "notes" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Account", 
                                    "account_name" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                    "Account Type", "account_type" )
                        ]
                    )
                ]
            }
        )
    }