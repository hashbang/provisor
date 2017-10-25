import os
import re
import sys
import tty

import base64
import grp
import pwd
import resource
import termios


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
        'about', 'abuse', 'main', 'data', 'example', 'jabber', 'legal', 'invite',
        'copyright', 'contact', 'board', 'feedback', 'support', 'anonymous', 'index',
        'inbox', 'payment', 'donate', 'calendar', 'dotfiles', 'billing', 'billings',
        'images', 'media', 'policy', 'manage', 'messages', 'mobile', 'official',
        'staging', 'development', 'staff', 'portal', 'forum', 'forums', 'pictures',
        'photos', 'status', 'finger', 'private', 'press', 'user', 'users', 'username',
        'usernames', 'sitemap', 'team', 'teams', 'account', 'accounts', 'chat', 'mail',
        'email', 'admin', 'admins', 'administrator', 'administrators', 'postmaster',
        'hostmaster', 'webmaster'
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
