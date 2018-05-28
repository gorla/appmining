""" this file contains all constants used by more than one luigi script """

import os

DANGEROUS_GROUPS = {'CALENDAR': {'READ_CALENDAR', 'WRITE_CALENDAR'},
                    'CAMERA': {'CAMERA'},
                    'CONTACTS': {'READ_CONTACTS', 'WRITE_CONTACTS',
                                 'GET_ACCOUNTS'},
                    'LOCATION': {'ACCESS_FINE_LOCATION',
                                 'ACCESS_COARSE_LOCATION'},
                    'MICROPHONE': {'RECORD_AUDIO'},
                    'PHONE': {'READ_PHONE_STATE', 'CALL_PHONE', 'READ_CALL_LOG',
                              'WRITE_CALL_LOG', 'ADD_VOICEMAIL', 'USE_SIP',
                              'PROCESS_OUTGOING_CALLS'},
                    'SENSORS': {'BODY_SENSORS'},
                    'SMS': {'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS',
                            'RECEIVE_WAP_PUSH', 'RECEIVE_MMS'},
                    'STORAGE': {'READ_EXTERNAL_STORAGE',
                                'WRITE_EXTERNAL_STORAGE'}
                    }

# reverse DANGEROUS_GROUPS -> 'READ_CALENDAR': 'CALENDAR'
DANGEROUS_GROUPS_MAPPING = {x: k for k, v in DANGEROUS_GROUPS.items() for x in v}

DANGEROUS_PERM_LIST = [item for sublist in DANGEROUS_GROUPS.values()
                       for item in sublist]

CONTENT_RESOLVER_PERMS = {'READ_CALENDAR',
                          'READ_CONTACTS',
                          'READ_PHONE_STATE',
                          'READ_CALL_LOG',
                          'READ_SMS',
                          'READ_EXTERNAL_STORAGE',
                          'WRITE_EXTERNAL_STORAGE'
                          }

CONTENT_RESOLVER_QUERY_API = ['<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,'
                              'java.lang.String[],android.os.Bundle,android.os.CancellationSignal)>',
                              '<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,'
                              'java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>',
                              '<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,'
                              'java.lang.String[],java.lang.String,java.lang.String[],java.lang.String,'
                              'android.os.CancellationSignal)>']

CONTENT_RESOLVER_INSERT_API = ['<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,'
                               'android.content.ContentValues)>',
                               '<android.content.ContentResolver: int insert(android.net.Uri,'
                               'android.content.ContentValues[])>']

CONTENT_RESOLVER_UPDATE_API = ['<android.content.ContentResolver: int update(android.net.Uri,'
                               'android.content.ContentValues,java.lang.String,java.lang.String[])>']

CONTENT_RESOLVER_API_LIST = CONTENT_RESOLVER_QUERY_API + CONTENT_RESOLVER_INSERT_API + CONTENT_RESOLVER_UPDATE_API

# get androguard api mappings folder path
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
AG_API_MAPPINGS_FOLDER = os.path.join(SCRIPT_DIR,
                                      'permission/androguard_api_mappings')

# preload all androguard mappings
AG_MAPPING = {}
for perm in DANGEROUS_PERM_LIST:
    mapping_fp = os.path.join(AG_API_MAPPINGS_FOLDER,
                              perm + '.txt')
    ag_perm_apis = [line.rstrip('\r\n') for line in open(mapping_fp)]
    AG_MAPPING[perm] = ag_perm_apis

# get the list of all apis stored in all permissions
AG_API_LIST = (set([j for i in AG_MAPPING.values() for j in i]))

AG_API_DICT = (dict([(api, 0) for api in AG_API_LIST]))

# all contract constants are part of android.provider. pkg
CONTENT_RESOLVER_CAT = {
    'content://com.android.contacts': 'contacts',
    'content://contacts': 'contacts',
    'content://mms-sms': 'sms',
    'content://sms': 'sms',
    'content://mms': 'sms',
    'content://com.android.voicemail': 'voicemail',
    #    'content://com.android.browser': 'browser',
    'content://com.android.calendar': 'calendar',
    'content://call_log': 'call_log',
    'content://media/external': 'external_content',
    #    'content://downloads': 'downloads',
    #    'content://settings': 'settings',
    #    'content://user_dictionary': 'user_dictionary',

    'android.provider.CalendarContract.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.Attendees.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.CalendarAlerts.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.CalendarCache.URI': 'calendar',
    'android.provider.CalendarContract.CalendarEntity.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.Calendars.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.Colors.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.EventDays.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.Events.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.EventsEntity.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.ExtendedProperties.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.Instances.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.Reminders.CONTENT_URI': 'calendar',
    'android.provider.CalendarContract.SyncState.CONTENT_URI': 'calendar',
    'android.provider.CallLog.CONTENT_URI': 'call_log',
    'android.provider.CallLog.Calls.CONTENT_URI': 'call_log',
    'android.provider.Contacts.CONTENT_URI': 'contacts',
    'android.provider.Contacts.ContactMethods.CONTENT_URI': 'contacts',
    'android.provider.Contacts.Extensions.CONTENT_URI': 'contacts',
    'android.provider.Contacts.GroupMembership.CONTENT_URI': 'contacts',
    'android.provider.Contacts.Groups.CONTENT_URI': 'contacts',
    'android.provider.Contacts.Organizations.CONTENT_URI': 'contacts',
    'android.provider.Contacts.People.CONTENT_URI': 'contacts',
    'android.provider.Contacts.Phones.CONTENT_URI': 'contacts',
    'android.provider.Contacts.Photos.CONTENT_URI': 'contacts',
    'android.provider.Contacts.Settings.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.AggregationExceptions.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.CommonDataKinds.Callable.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.CommonDataKinds.Contactables.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.CommonDataKinds.Email.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.CommonDataKinds.Phone.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.CommonDataKinds.StructuredPostal.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.Contacts.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.Data.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.DeletedContacts.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.Directory.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.DisplayPhoto.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.Groups.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.Profile.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.ProfileSyncState.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.ProviderStatus.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.RawContacts.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.RawContactsEntity.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.Settings.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.StatusUpdates.CONTENT_URI': 'contacts',
    'android.provider.ContactsContract.SyncState.CONTENT_URI': 'contacts',
    'android.provider.MediaStore.Audio.Albums.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Audio.Artists.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Audio.Genres.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Audio.Media.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Audio.Playlists.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Video.Media.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI': 'external_content',
    'android.provider.Settings.Global.CONTENT_URI': 'settings',
    'android.provider.Settings.Secure.CONTENT_URI': 'settings',
    'android.provider.Settings.System.CONTENT_URI': 'settings',
    'android.provider.Telephony.Carriers.CONTENT_URI': 'sms',
    'android.provider.Telephony.Mms.CONTENT_URI': 'sms',
    'android.provider.Telephony.Mms.Draft.CONTENT_URI': 'sms',
    'android.provider.Telephony.Mms.Inbox.CONTENT_URI': 'sms',
    'android.provider.Telephony.Mms.Outbox.CONTENT_URI': 'sms',
    'android.provider.Telephony.Mms.Rate.CONTENT_URI': 'sms',
    'android.provider.Telephony.Mms.Sent.CONTENT_URI': 'sms',
    'android.provider.Telephony.MmsSms.CONTENT_URI': 'sms',
    'android.provider.Telephony.MmsSms.PendingMessages.CONTENT_URI': 'sms',
    'android.provider.Telephony.ServiceStateTable.CONTENT_URI': 'sms',
    'android.provider.Telephony.Sms.CONTENT_URI': 'sms',
    'android.provider.Telephony.Sms.Conversations.CONTENT_URI': 'sms',
    'android.provider.Telephony.Sms.Draft.CONTENT_URI': 'sms',
    'android.provider.Telephony.Sms.Inbox.CONTENT_URI': 'sms',
    'android.provider.Telephony.Sms.Outbox.CONTENT_URI': 'sms',
    'android.provider.Telephony.Sms.Sent.CONTENT_URI': 'sms',
    'android.provider.Telephony.Threads.CONTENT_URI': 'sms',
    'android.provider.UserDictionary.CONTENT_URI': 'user_dictionary',
    'android.provider.UserDictionary.Words.CONTENT_URI': 'user_dictionary',
    'android.provider.VoicemailContract.Status.CONTENT_URI': 'voicemail',
    'android.provider.VoicemailContract.Voicemails.CONTENT_URI': 'voicemail'
}

# maps CONTENT_URI categories to required permission for read queries
CONTENT_RESOLVER_READ_PERM_MAPPING = {
    'contacts': ['READ_CONTACTS'],
    'sms': ['READ_SMS'],
    'calendar': ['READ_CALENDAR'],
    'call_log': ['READ_CALL_LOG'],
    'external_content': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE']
}

# maps CONTENT_URI categories to required permission for write queries
CONTENT_RESOLVER_WRITE_PERM_MAPPING = {
    'contacts': ['WRITE_CONTACTS'],
    'voicemail': ['ADD_VOICEMAIL'],
    'calendar': ['WRITE_CALENDAR'],
    'call_log': ['WRITE_CALL_LOG'],
    'external_content': ['WRITE_EXTERNAL_STORAGE']
}
