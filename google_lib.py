#!/usr/bin/python2.7
#
# This file is intended as a library
# You should already have a credentials file checked into the repo, so you shouldn't need to do this
# But, shoudl we change the account it's registered with or something similar note that this file can be
# run as a binary. When run as a binary it will run through the oauth2 authentication protocol to acquire
# A credentials file which is then written to the "auth" directory.
#
# This is hard-coded to use robot@smalladvntures.net (see the auth/auth.py). So when generating the
# credentials file be sure to log in as robbie robot.

from __future__ import print_function

# NOTE: requires pyopenssl to work

import httplib2
import os
import sys

from apiclient import errors
from apiclient.discovery import build
from oauth2client.client import SignedJwtAssertionCredentials
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage


# It may eventually be worthwhile to track Ids as well... in case we run two
# simultanious identical classes
# I'm ignoring that for now though. location+name+time is likely sufficient
class Event(object):
  def __init__(self, cal_event):
    self._event = cal_event
    self._modified = False

  def title(self):
    return self._event['summary']

  def time(self):
    return str(self._event['start']['dateTime']).replace('T','/')

  def timezone(self):
    return str(self._event['start'].get('timeZone', ''))

  def location(self):
    return str(self._event.get('location',''))

  def set_location(self, loc):
    if self._event['location'] != loc:
      self._event['location'] = loc
      self._modified = True

  def description(self):
    return str(self._event.get('description', ''))

  def set_description(self, desc):
    if self._event.get('description') != desc:
      self._event['description'] = desc
      self._modified = True

  def get_dict(self):
    return self._event

  def clear_modified(self):
    self._modified = False

  def is_modified(self):
    return self._modified

  def __str__(self):
    s = self._event['summary'] + \
        '_' + self.location() + \
        '_' + self.time() + \
        '_' + self.timezone()
    return s

  def time_and_location(self):
    return self.location() + ' ' + self.time() + ' ' + self.timezone()


class Perm(object):
  def __init__(self, read=None, write=None):
    self._read = set(read or [])
    self._write = set(write or [])

  # Implement the basic set operations
  def __getattr__(self, attr):
    op_list = ['__and__', '__or__', '__ror__', '__sub__', '__rsub__', '__xor__',
            '__rxor__',
            'difference', 'intersection', 'union']
    comp_list = ['__eq__', '__ge__', '__gt__', '__le__', '__lt__', '__ne__']
    if attr in op_list:
      def func(other):
        read = getattr(self._read, attr)(other._read)
        write = getattr(self._write, attr)(other._write)
        return Perm(read,write)
      return func
    if attr in comp_list:
      def func(other):
        result1 = getattr(self._read, attr)(other._read)
        result2 = getattr(self._write, attr)(other._write)
        return result1 and result2
      return func
    else:
      raise AttributeError

  def readers(self):
    return list(self._read)

  def writers(self):
    return list(self._write)

  def roles_dict(self):
    return dict([(n, 'reader') for n in self._read] + [(n,'writer') for n in self._write])

  def __str__(self):
    return str({'read': self._read, 'write': self._write})


# Takes an object with add_acl, del_acl, and get_acl methods
def set_acls_helper(object, perms, id):
  # Get existing permissions
  existing_perms = object.get_perms(id)
  print('existing perms: ', str(existing_perms))
  # compute changes
  add_perms = perms.difference(existing_perms)
  add_roles = add_perms.roles_dict() 
  rem_perms = existing_perms.difference(perms)
  rem_roles = rem_perms.roles_dict() 
  # Add permissions
  for n,r in add_roles.items():
    object.add_acl(r, n, id)
  # Remove permissions
  for n,r in rem_roles.items():
    object.del_acl(r, n, id)


class Calendar(object):
  def __init__(self, key_path, calendarId='primary'):
    self._calendarId = calendarId
    storage = Storage(key_path + '/oauth_credentials')
    self._credentials = storage.get()
    self._http = httplib2.Http()
    self._http = self._credentials.authorize(self._http)

    self._service = build('calendar', 'v3', http=self._http)

  def add_acl(self, role, user, id=None):
    if not id:
      id = self._calendarId
    print('cal: adding ' + user + ' as ' + role)
    if user == 'default':
      rule = {'role': role, 'scope': {'type': 'default'}}
    else:  
      rule = {'role': role, 'scope': {'type': 'user', 'value': user}}
    self._service.acl().insert(calendarId=id, body=rule).execute()

  def del_acl(self, role, user, id=None):
    if not id:
      id = self._calendarId
    acls = self.get_acls(id)
    for acl in acls['items']:
      if acl['scope']['value'] == user:
        # make sure the role matches
        # we count owner as writer
        if role == 'writer':
          if acl['role'] not in ['writer', 'owner']:
            continue
        elif acl['role'] != role:
          continue
        print('cal: deleting ' + user + ' from ' + role + ' id:' + acl['id'])
        self._service.acl().delete(calendarId=id, ruleId=acl['id']).execute()
        return
    print('Could not find ACL to match ' + user + ' as ' + role)

  def get_acls(self, id=None):
    if not id:
      id = self._calendarId
    acls = self._service.acl().list(calendarId=id).execute()
    if not acls:
      raise Exception('Failed to fetch Calendar ACLs for id='+id)
    return acls

  def get_perms(self, id=None):
    if not id:
      id = self._calendarId
    acls = self.get_acls(id)
    read = []
    write = []
    for el in acls['items']:
      # check if this is the special "default" permission
      if el['scope']['type'] == 'default':
        read.append('default') 
      if el['role'] == 'owner' or el['role'] == 'writer':
        write.append(el['scope']['value'])
      if el['role'] == 'reader':
        read.append(el['scope']['value'])
    p = Perm(read, write)
    return p

  def set_acls(self, perms, id=None):
    if not id:
      id = self._calendarId
    set_acls_helper(self, perms, id)  

  def get_events(self, id=None):
    if not id:
      id = self._calendarId
    all_events = []
    page_token = None
    while True:
      events = self._service.events().list(calendarId=id, pageToken=page_token).execute()
      all_events += [Event(e) for e in events['items']]
      page_token = events.get('nextPageToken')
      if not page_token:
        break
    return all_events 

  def update_event(self, event, calendarId=None):
    print('Called update_event')
    if not event.is_modified():
      return event
    print('Updating event: ' + str(event))
    if not calendarId:
      calendarId = self._calendarId
    e = event.get_dict()
    updated_event = self._service.events().update(calendarId=calendarId, eventId=e['id'], body=e).execute()
    return Event(updated_event)


# We run all translations through the translation table.
# A bonus is caching, but the primary reason is to build the id_to_user table.
# This allows us to translate id's to users for users we've seen.
class TranslationTable(object):
  def __init__(self, google_drive):
    self._drive = google_drive
    self._user_to_id={}
    self._id_to_user={}

  def set_drive(self, google_drive):
    self._drive = google_drive

  def user_to_id(self, u):
    id = self._user_to_id.get(u)
    if id != None:
      return id
    id = self._drive.raw_user_to_id(u)
    self._user_to_id[u] = id
    self._id_to_user[id] = u 
    return id

  # This is best effort, we translate what we can
  # What we can't we just let fall through as id's :(
  # This exists because you can't give an "Id" permissions, you need a user
  def id_to_user(self, id):
    u = self._id_to_user.get(id)
    if u != None:
      return u
    return id


class Drive(object):
  def __init__(self, key_path):
    # This looks like it's for caching, while it happens to act as a cache
    # that isn't important.
    # This allows us to add permissions with "ids" instead of users
    # Theoretically we could do some computations with user instead of id
    # but this complicates the logic, so we translate everything to ids
    # and then backtranslate to users when we have to
    #
    # Note that this always works because we're only adding id's that
    # initially came from users we knew about. In general though you can't
    # translate an arbitrary id to a user
    #
    # TODO: right now when we're looking at users and id's is poorly boxed
    # and not clear due to variable names... needs fixed
    # My guess is that computing on "users" would be cleaner overall
    # we can use what we know to translate id's to users where we have to
    # when we do a "get_acls" call
    self._translation = TranslationTable(self)
    storage = Storage(key_path + '/oauth_credentials')
    self._credentials = storage.get()

    self._http = httplib2.Http()
    self._http = self._credentials.authorize(self._http)
    self._service = build('drive', 'v2', http=self._http)

  def raw_user_to_id(self, user):
    id_resp = self._service.permissions().getIdForEmail(email=user).execute()
    return id_resp['id']

  def user_to_id(self, user):
    return self._translation.user_to_id(user)

  def id_to_user(self, id):
    return self._translation.id_to_user(id)

  # Drive doesn't let us know a permissions email address
  # instead we operate on these "ids" that can be computed
  # from email addresses. This translates a perm into the
  # id format
  def translate_perms(self, perms):
    read = [self.user_to_id(r) for r in perms.readers()]
    write = [self.user_to_id(w) for w in perms.writers()]
    p = Perm(read,write)
    return p
  
  # Non-mutative
  def retrieve_all_files(self):
    result = []
    page_token = None
    while True:
      try:
        param = {}
        if page_token:
          param['pageToken'] = page_token
        files = self._service.files().list(**param).execute()

        result.extend(files['items'])
        page_token = files.get('nextPageToken')
        if not page_token:
          break
      except errors.HttpError as error:
        print('An error occurred: %s' % error)
        break
    return result

  # Non-mutative
  def get_file_handle(self, title):
    files = self.retrieve_all_files()
    fi = None
    for f in files:
      if title == f['title']:
        fi = f
    return fi

  # Non-mutative
  def get_acls(self, id):
    acls = self._service.permissions().list(fileId=id).execute()
    if not acls:
      raise Exception('Failed to fetch Drive ACLs for id='+id)
    return acls

  # Non-mutative
  def get_perms(self, id):
    acls = self.get_acls(id)
    read = []
    write = []
    for el in acls['items']:
      if el['role'] == 'owner' or el['role'] == 'writer':
        write.append(el['id'])
      if el['role'] == 'reader':
        read.append(el['id'])
    return Perm(read, write)

  def add_acl(self, role, user, id):
    # it's not possible to add a permission for an "id" we need a user
    # so we fake what we can by translating users in our translation table
    actual_user = self.id_to_user(user)
    print('drive: adding ' + user + ' which is ' + actual_user + ' as ' + role)
    rule = {'role': role, 'type': 'user', 'value': actual_user}
    self._service.permissions().insert(fileId=id, body=rule, sendNotificationEmails=False).execute()

  def del_acl(self, role, user, id):
    acls = self.get_acls(id)
    for acl in acls['items']:
      if acl['id'] == user:
        # make sure the role matches
        # we count owner as writer
        if role == 'writer':
          if acl['role'] not in ['writer', 'owner']:
            continue
        elif acl['role'] != role:
          continue
        print('cal: deleting ' + user + ' from ' + role + ' id:' + acl['id'])
        self._service.permissions().delete(fileId=id, permissionId=acl['id']).execute()
        return
    print('Could not find ACL to match ' + user + ' as ' + role)


  def set_acls(self, perms, id):
    translated_perms = self.translate_perms(perms)
    set_acls_helper(self, translated_perms, id)  

  # Idempotently creates a file
  # if the file already exists fixes permissions and returns a handle to it
  def create_file(self, title, typ, perms):
    f = self.get_file_handle(title)
    if not f:
      print('creating: ' + title)
      if typ == 'spreadsheet':
        body = {'title': title, 'description': '', 'mimeType': 'application/vnd.google-apps.spreadsheet'}
      else:
        raise Exception('Unknown "typ" argument: ' + typ)
      f = self._service.files().insert(body=body).execute() 
    self.set_acls(perms, f['id'])
    return f

  # Not terribly idempotent :(
  # Attempt to delete an already deleted file *is* allowed though, no crash
  def delete_file(file_id):
    response = drive_service.files().delete(fileId=file_id).execute()
    return response

def authorize(credential_filename):
  flow = flow_from_clientsecrets(
      '/var/www/website_src/auth/client_secret_63808424265.apps.googleusercontent.com.json',
      scope='https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive',
      redirect_uri='urn:ietf:wg:oauth:2.0:oob'
     # redirect_uri='http://smalladventures.net'
      )
  auth_uri = flow.step1_get_authorize_url()
  print(auth_uri)
  print('Enter the code presented at the above URL and press enter')
  code = os.read(0,100)
  credentials = flow.step2_exchange(code)
  http = httplib2.Http()
  http = credentials.authorize(http)
  storage = Storage(credential_filename)
  storage.put(credentials)

#### This is for running it as a binary to get the credentials

def main(argv=None):
  tmp_curfiledir = os.path.dirname(sys.argv[0])
  credential_filename = tmp_curfiledir + '/../auth/oauth_credentials'
  authorize(credential_filename)


if __name__ == "__main__":
    sys.exit(main())
