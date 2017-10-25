import os
import re
import sys
import tty

import base64
import grp
import pwd
import resource
import termios


def make_salt():
  salt = ""
  while len(salt) < 8:
    c = os.urandom(1)
    if re.match('[a-zA-Z0-9./]', c):
      salt += c
  return salt


def drop_privileges(uid_name='nobody', gid_name='nogroup'):

    if os.getuid() != 0:  # not root. #yolo
        return

    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    os.setgroups([])
    os.setgid(running_gid)
    os.setuid(running_uid)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def validate_pubkey(value):
    if len(value) > 8192 or len(value) < 80:
      raise ValueError("Expected length to be between 80 and 8192 characters")

    value = value.replace("\"", "").replace("'", "").replace("\\\"", "")
    value = value.split(' ')
    types = [ 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
              'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss', 'ssh-ed25519' ]
    if value[0] not in types:
        raise ValueError(
            "Expected " + ', '.join(types[:-1]) + ', or ' + types[-1]
        )

    try:
        base64.decodestring(bytes(value[1]))
    except:
        raise ValueError("Expected string of base64 encoded data")

    return "%s %s" % (value[0], value[1])


def validate_username(value):
    reserved_usernames = [
        # Names that might be used for fishing
        'about', 'account', 'accounts', 'admin', 'administrator',
        'administrators', 'admins', 'anonymous', 'billing', 'billings', 'board',
        'calendar', 'contact', 'copyright', 'data', 'development', 'donate',
        'dotfiles', 'email', 'example', 'feedback', 'forum', 'forums', 'images',
        'inbox', 'index', 'invite', 'jabber', 'legal', 'main', 'manage', 'media',
        'messages', 'mobile', 'official', 'payment', 'photos', 'pictures',
        'policy', 'portal', 'press', 'private', 'sitemap', 'staff', 'staging',
        'status', 'teams', 'user', 'username', 'usernames', 'users',

        # #! service names
        'chat', 'finger', 'git', 'im', 'irc', 'ldap', 'mail', 'voip', 'www'

        # Non-RFC2142 email aliases
        'mailer-daemon', 'nobody', 'root', 'team'

        # RFC2142 mailbox names
        ## Business related
        'info', 'marketing', 'sales', 'support',

        ## Network operations
        'abuse', 'noc', 'security'

        ## Support for specific services
        'ftp', 'hostmaster', 'news', 'usenet',
        'uucp', 'postmaster', 'webmaster', 'www'
    ]

    # Regexp must be kept in sync with
    #  https://github.com/hashbang/hashbang.sh/blob/master/src/hashbang.sh#L178-191
    if re.compile(r"^[a-z][a-z0-9]{,30}$").match(value) is None:
        raise ValueError('Username is invalid')
    if value in reserved_usernames:
        raise ValueError('Username is reserved')
    user_exists = True
    try:
        pwd.getpwnam(value)
    except:
        user_exists = False
    if user_exists:
        raise ValueError('Username already exists')
    return value
