import copy
import ldap
import ldap.modlist
import time
import crypt
import os
import re
from utils import make_salt
from ConfigParser import ConfigParser

config = ConfigParser()

config.read([
  '/etc/provisor.ini',
  os.path.expanduser('~/.provisor.ini')
])

LDAP_URI = config.get('ldap','uri')
LDAP_USER = config.get('ldap','user')
LDAP_PASSWORD = config.get('ldap','password')
USER_BASE = config.get('ldap','user-base')
GROUP_BASE = config.get('ldap','group-base')
CACERTFILE = config.get('ldap','ca-certfile')

DEFAULT_SHELL = config.get('provisor','default-shell')
MIN_UID = config.get('provisor','min-uid')
MAX_UID = config.get('provisor','max-uid')
EXCLUDED_UIDS = [e.strip() for e in config.get('provisor', 'excluded-uids').split(',')]

class Provisor(object):
  def __init__(self):
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,CACERTFILE)
    self.con = ldap.initialize(LDAP_URI)
    self.con.set_option(ldap.OPT_X_TLS_DEMAND, True)
    self.con.start_tls_s()
    self.con.simple_bind_s(LDAP_USER, LDAP_PASSWORD)

  """ Does not work, dont know why """
  def whoami(self):
    return self.con.whoami_s()

  def list_users(self):
    users = []
    results = self.con.search_s(USER_BASE, ldap.SCOPE_ONELEVEL, '(objectClass=*)', ("uid",), 0)
    for r in results:
      for attrs in r[1]:
        users.append(r[1][attrs][0])
    return tuple(users)

  def list_groups(self):
    groups = []
    results = self.con.search_s(GROUP_BASE, ldap.SCOPE_ONELEVEL, '(objectClass=*)', ("cn",), 0)
    for r in results:
      for attrs in r[1]:
        groups.append(r[1][attrs][0])
    return tuple(groups)

  def group_exists(self, group):
    try:
      if self.con.compare_s("cn={0},{1}".format(group, GROUP_BASE), "cn", group) == 1:
        return True
      else:
        return False
    except ldap.NO_SUCH_OBJECT:
      return False

  def user_exists(self, user):
    try:
      if self.con.compare_s("uid={0},{1}".format(user, USER_BASE), "uid", user) == 1:
        return True
      else:
        return False
    except ldap.NO_SUCH_OBJECT:
      return False

  """ Returns the next uid for use """
  def next_uid(self):
    uids = []
    results = self.con.search_s(USER_BASE, ldap.SCOPE_ONELEVEL, '(objectClass=*)', ("uidNumber",), 0)
    for r in results:
      for attrs in r[1]:
        uids.append(int(r[1][attrs][0]))
    uids.sort()
    for u in range(MIN_UID,MAX_UID,1):
      if u in uids or u in EXCLUDED_UIDS:
        continue
      return u

  """ Returns the next gid for use """
  def next_gid(self):
    gids = []
    results = self.con.search_s(GROUP_BASE, ldap.SCOPE_ONELEVEL, '(objectClass=*)', ("gidNumber",), 0)
    for r in results:
      for attrs in r[1]:
        gids.append(int(r[1][attrs][0]))
    gids.sort()
    for g in range(MIN_UID,MAX_UID,1):
      if g in gids or g in EXCLUDED_UIDS:
        continue
      return g


  def add_group(self, groupname, gid=-1):
    if gid < 0:
      self.next_gid()

    ml = {
     'objectClass': [ 'top','posixGroup'],
     'cn': [ groupname ],
     'gidNumber': [ str(gid) ],
    }
    ml = ldap.modlist.addModlist(ml)
    self.con.add_s("cn={0},{1}".format(groupname, GROUP_BASE), ml)


  def del_group(self, groupname):
    self.con.delete_s("cn={0},{1}".format(groupname, GROUP_BASE))


  def is_group_member(self, group, user):
    try:
      if self.con.compare_s("cn={0},{1}".format(group, GROUP_BASE), "memberUid", user) == 1:
        return True
      else:
        return False
    except ldap.NO_SUCH_OBJECT:
      return False


  def list_group_members(self, group):
    members = []
    results = self.con.search_s("cn={0},{1}".format(group,GROUP_BASE), 
                                      ldap.SCOPE_BASE, '(objectClass=*)', ("memberUid",), 0)
    for r in results:
      for attrs in r[1]:
        for e in r[1][attrs]:
          members.append(e)
    return members


  def add_group_member(self, group, user):
    ml = { 'memberUid': [ user ] }
    ml = ldap.modlist.modifyModlist({}, ml, ignore_oldexistent=1)
    self.con.modify_s("cn={0},{1}".format(group, GROUP_BASE), ml)


  def del_group_member(self, group, user):
    old = self.con.search_s("cn={0},{1}".format(group, GROUP_BASE), ldap.SCOPE_BASE, '(objectClass=*)', ("memberUid",), 0)
    old = old[0][1]
    new = copy.deepcopy(old)
    new['memberUid'].remove(user)
    ml = ldap.modlist.modifyModlist(old, new)
    self.con.modify_s("cn={0},{1}".format(group, GROUP_BASE), ml)


  """ Attempt to modify a users entry """
  def modify_user(self, username, pubkey=None,
                  shell=None, homedir=None, password=None,
                  uid=None, gid=None, lastchange=None, 
                  nextchange=None, warning=None, raw_passwd=None,
                  hostname=None):
    old = self.con.search_s("uid={0},{1}".format(username, USER_BASE), ldap.SCOPE_BASE, '(objectClass=*)', ("*",), 0)
    old = old[0][1]
    new = copy.deepcopy(old)

    if 'shadowAccount' not in new['objectClass']:
      new['objectClass'].append('shadowAccount')

    if 'inetLocalMailRecipient' not in new['objectClass']:
      new['objectClass'].append('inetLocalMailRecipient')

    if pubkey:
      if 'sshPublicKey' in new:
        del(new['sshPublicKey'])
      new['sshPublicKey'] = [ str(pubkey) ]

    if shell:
      if 'loginShell' in new:
        del(new['loginShell'])
      new['loginShell'] = [ str(shell) ]

    if homedir:
      if 'homeDirectory' in new:
        del(new['homeDirectory'])
      new['homeDirectory'] = [ str(homedir) ]

    if password:
      password = '{crypt}' + crypt.crypt(password, "$6${0}".format(make_salt()))
      if 'userPassword' in new:
        del(new['userPassword'])
      new['userPassword'] = [ str(password) ]

      if 'shadowLastChange' in new:
        del(new['shadowLastChange'])
      new['shadowLastChange'] = [ str(int(time.time() / 86400)) ]

    if raw_passwd:
      password = '{crypt}' + raw_passwd 
      if 'userPassword' in new:
        del(new['userPassword'])
      new['userPassword'] = [ str(password) ]

      if 'shadowLastChange' in new:
        del(new['shadowLastChange'])
      new['shadowLastChange'] = [ str(int(time.time() / 86400)) ]

    if lastchange:
      if 'shadowLastChange' in new:
        del(new['shadowLastChange'])
      new['shadowLastChange'] = [ str(int(time.time() / 86400)) ]

    if uid:
      if 'uidNumber' in new:
        del(new['uidNumber'])
      new['uidNumber'] = [ str(uid) ]

    if gid:
      if 'gidNumber' in new:
        del(new['gidNumber'])
      new['gidNumber'] = [ str(gid) ]

    if 'shadowInactive' not in new:
      new['shadowInactive'] = [ '99999' ]

    if 'shadowExpire' not in new:
      new['shadowExpire'] = [ '99999']

    if hostname:
      if 'host' in new:
        del(new['host'])
      new['host'] = str(hostname)
      if 'mailRoutingAddress' in new:
        del(new['mailRoutingAddress'])
      new['mailRoutingAddress'] = [ '{0}@hashbang.sh'.format(username) ]
      if 'mailHost' in new:
        del(new['mailHost'])
      new['mailHost'] = [ 'smtp:{0}'.format(hostname) ]

    ml = ldap.modlist.modifyModlist(old, new)
    self.con.modify_s("uid={0},{1}".format(username, USER_BASE), ml)


  """ Adds a user, takes a number of optional defaults but the username and public key are required """
  def add_user(self, username, pubkey, hostname,
                shell=DEFAULT_SHELL, homedir=None, password=None,
                uid=-1, gid=-1,
                lastchange=-1, nextchange=99999, warning=7, raw_passwd=None):

    if not homedir:
      homedir="/home/{0}".format(username)

    if uid < 0:
      uid = self.next_uid()
    if gid < 0:
      gid = self.next_gid()

    if lastchange < 0:
      lastchange = int(time.time() / 86400)

    if password == None:
      password = '{crypt}!'
    elif raw_passwd:
      password = '{crypt}' + raw_passwd
    else:
      password = '{crypt}' + crypt.crypt(password, "$6${0}".format(make_salt()))

    ml = {
      'objectClass': [ 'account', 'posixAccount', 'top' ,'shadowAccount', 'ldapPublicKey', 'inetLocalMailRecipient' ],
      'uid' : [ username ],
      'cn' : [ username],
      'uidNumber' : [ str(uid) ],
      'gidNumber' : [ str(gid) ],
      'loginShell' : [ DEFAULT_SHELL ],
      'homeDirectory' : [ homedir ],
      'shadowLastChange' : [ str(lastchange) ],
      'shadowMax' : [ str(nextchange) ],
      'shadowWarning' : [ str(warning) ],
      'shadowInactive' : [ str(99999) ],
      'shadowExpire' : [ str(99999) ],
      'userPassword' : [ str(password) ],
      'sshPublicKey' : [ str(pubkey) ],
      'host' : [ str(hostname) ],
      'mailRoutingAddress' : [ '{0}@hashbang.sh'.format(username) ],
      'mailHost' : [ str('smtp:'+hostname) ],
    }

    ml = ldap.modlist.addModlist(ml)
    self.con.add_s("uid={0},{1}".format(username, USER_BASE), ml)


  def del_user(self, username):
    self.con.delete_s("uid={0},{1}".format(username, USER_BASE))


  def __del__(self):
    self.con.unbind_s()
