'''
NFI -- Silensec's Nyuki Forensics Investigator

Copyright (C) 2014  George Nicolaou (george[at]silensec[dot]com)
                    Silensec Ltd.
                    
                    Juma Fredrick (j.fredrick[at]silensec[dot]com)
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

from IApp import IApp, KnownTable, DataTypes
import ConvertUtils


class com_skype_raider(IApp):

    name = 'com.skype.raider'
    cname = 'Android Skype'
    databases = {
        'queue.db': [
            KnownTable('history', None,
                {'stored_time': ConvertUtils.UnixTimestamp,
                 'started_time': ConvertUtils.UnixTimestamp,
                 'completed_time': ConvertUtils.UnixTimestamp},
                {'stored_time': DataTypes.DATE,
                 'started_time': DataTypes.DATE,
                 'completed_time': DataTypes.DATE}),
            KnownTable('queue', None,
                {'stored_time': ConvertUtils.UnixTimestamp,
                 'started_time': ConvertUtils.UnixTimestamp},
                {'stored_time': DataTypes.DATE,
                 'started_time': DataTypes.DATE})],
        'qik_main.db': [
            KnownTable('media_items', None,
                {'creation_time': ConvertUtils.UnixTimestamp,
                 'edit_time': ConvertUtils.UnixTimestamp,
                 'fname_exp_date': ConvertUtils.UnixTimestamp},
                {'creation_time': DataTypes.DATE,
                 'edit_time': DataTypes.DATE,
                 'fname_exp_date': DataTypes.DATE}),
            KnownTable('sharings', None,
                {'created_at': ConvertUtils.UnixTimestamp,
                 'expires_at': ConvertUtils.UnixTimestamp},
                {'created_at': DataTypes.DATE,
                 'expires_at': DataTypes.DATE}),
            KnownTable('streams', None,
                {'creation_date': ConvertUtils.UnixTimestamp},
                {'creation_date': DataTypes.DATE,})
        ],
        'statistics.db': [
            KnownTable('connectivity_statistics', None,
                {'timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE}),
            KnownTable('message_statistics', None,
                {'timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE})],
        'msn.db': [
            KnownTable('queue', None,
                {'timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE})
        ],
        'main.db': [
            KnownTable('Accounts', None, 
                {'registration_timestamp': ConvertUtils.UnixTimestamp,
                 'profile_timestamp': ConvertUtils.UnixTimestamp,
                 'lastonline_timestamp': ConvertUtils.UnixTimestamp,
                 'lastused_timestamp': ConvertUtils.UnixTimestamp,
                 'mood_timestamp': ConvertUtils.UnixTimestamp,
                 'authorized_time': ConvertUtils.UnixTimestamp,},
                {'registration_timestamp': DataTypes.DATE,
                 'profile_timestamp': DataTypes.DATE,
                 'lastonline_timestamp': DataTypes.DATE,
                 'lastused_timestamp': DataTypes.DATE,
                 'mood_timestamp': DataTypes.DATE,
                 'authorized_time': DataTypes.DATE,}),
            KnownTable('Alerts', None,
                {'timestamp': ConvertUtils.UnixTimestamp,
                 "meta_expiry": ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE,
                 "meta_expiry":DataTypes.DATE}),
            KnownTable('CallMembers', None,
                {'next_redial_time': ConvertUtils.UnixTimestamp,
                 'start_timestamp': ConvertUtils.UnixTimestamp,
                 'creation_timestamp': ConvertUtils.UnixTimestamp},
                {'next_redial_time': DataTypes.DATE,
                 'start_timestamp': DataTypes.DATE,
                 'creation_timestamp': DataTypes.DATE}),
            KnownTable('Calls', None,
                {'begin_timestamp': ConvertUtils.UnixTimestamp,
                 'start_timestamp': ConvertUtils.UnixTimestamp},
                {'begin_timestamp': DataTypes.DATE,
                 'start_timestamp': DataTypes.DATE}),
            KnownTable('Chats', None,
                {'timestamp': ConvertUtils.UnixTimestamp,
                 'activity_timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE,
                 'activity_timestamp': DataTypes.DATE}),
            KnownTable('Contacts', None,
                {'profile_timestamp': ConvertUtils.UnixTimestamp,
                 'avatar_timestamp': ConvertUtils.UnixTimestamp,
                 'mood_timestamp': ConvertUtils.UnixTimestamp,
                 'authreq_timestamp': ConvertUtils.UnixTimestamp,
                 'lastonline_timestamp': ConvertUtils.UnixTimestamp,
                 'lastused_timestamp': ConvertUtils.UnixTimestamp,
                 'authorized_time': ConvertUtils.UnixTimestamp,
                 'sent_authrequest_time': ConvertUtils.UnixTimestamp},
                {'profile_timestamp': DataTypes.DATE,
                 'avatar_timestamp': DataTypes.DATE,
                 'mood_timestamp': DataTypes.DATE,
                 'authreq_timestamp': DataTypes.DATE,
                 'lastonline_timestamp': DataTypes.DATE,
                 'lastused_timestamp': DataTypes.DATE,
                 'authorized_time': DataTypes.DATE,
                 'sent_authrequest_time': DataTypes.DATE,}),
            KnownTable('Conversations', None,
                {'live_start_timestamp': ConvertUtils.UnixTimestamp,
                 'inbox_timestamp': ConvertUtils.UnixTimestamp,
                 'last_activity_timestamp': ConvertUtils.UnixTimestamp,
                 'creation_timestamp': ConvertUtils.UnixTimestamp,}, 
                {'live_start_timestamp': DataTypes.DATE,
                 'inbox_timestamp': DataTypes.DATE,
                 'last_activity_timestamp': DataTypes.DATE,
                 'creation_timestamp': DataTypes.DATE,}),
            KnownTable('Messages', None,
                {'timestamp': ConvertUtils.UnixTimestamp,
                 'edited_timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE,
                 'edited_timestamp': DataTypes.DATE}),
            KnownTable('Participants', None,
                {'live_start_timestamp': ConvertUtils.UnixTimestamp,
                 'next_redial_time': ConvertUtils.UnixTimestamp},
                {'live_start_timestamp': DataTypes.DATE,
                 'next_redial_time': DataTypes.DATE}),
            KnownTable('SMSes', None,
                {'timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE}),
            KnownTable('Transfers', None,
                {'starttime': ConvertUtils.UnixTimestamp,
                 'finishtime': ConvertUtils.UnixTimestamp,
                 'accepttime': ConvertUtils.UnixTimestamp},
                {'starttime': DataTypes.DATE,
                 'finishtime': DataTypes.DATE,
                 'accepttime': DataTypes.DATE}),
            KnownTable('VideoMessages', None,
                {'creation_timestamp': ConvertUtils.UnixTimestamp},
                {'creation_timestamp': DataTypes.DATE}),
            KnownTable('Videos', None,
                {'timestamp': ConvertUtils.UnixTimestamp,
                 'ss_timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE,
                 'ss_timestamp': DataTypes.DATE}),
            KnownTable('Voicemails', None,
                {'timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE}),
        ],
        'cache_db.db': [
            KnownTable('assets', None,
                {'access_time': ConvertUtils.UnixTimestamp},
                {'access_time': DataTypes.DATE})
        ],
        'storage_db.db': [
            KnownTable('contents', None,
                {'expiry_date': ConvertUtils.UnixTimestamp,
                 'upload_time': ConvertUtils.UnixTimestamp},
                {'expiry_date': DataTypes.DATE,
                 'upload_time': DataTypes.DATE}),
            KnownTable('documents', None,
                {'expiry_date': ConvertUtils.UnixTimestamp,
                 'sync_time': ConvertUtils.UnixTimestamp},
                {'expiry_date': DataTypes.DATE,
                 'sync_time': DataTypes.DATE})
        ],
        'bistats.db': [
            KnownTable('events', None,
                {'timestamp': ConvertUtils.UnixTimestamp},
                {'timestamp': DataTypes.DATE}),
            KnownTable('reports', None, 
                {'created_time': ConvertUtils.UnixTimestamp,
                 'delivered_time': ConvertUtils.UnixTimestamp,
                 'period_start': ConvertUtils.UnixTimestamp,
                 'period_end': ConvertUtils.UnixTimestamp}, 
                {'created_time': DataTypes.DATE,
                 'delivered_time': DataTypes.DATE,
                 'period_start': DataTypes.DATE,
                 'period_end': DataTypes.DATE})
            ],
        }

    def __init__(self):
        self.known = True