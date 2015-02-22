import re
import os
import sys
import tty
import termios

def make_salt():
  salt = ""
  while len(salt) < 8:
    c = os.urandom(1)
    if re.match('[a-zA-Z0-9./]', c):
      salt += c
  return salt

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
    # Value CANNOT include quotes, so we MAKE SURE there are no quotes around it yet.
    value = value.replace( "\"", "" ).replace( "'", "" ).replace("\\\"", "" )
    value = value.split( ' ' )
    if value[0] != "ssh-rsa" and value[0] != "ssh-dsa":
        raise ValueError( "Public Key Is Invalid" )
    try:
        base64.decodestring(bytes(value[1],'utf8'))
    except TypeError:
        raise ValueError("Public Key Is Invalid")
    except:
        raise ValueError('Public Key Is Invalid')

    return "%s %s" % (value[0],value[1])


def validate_username(value):
    reserved_usernames = [
        'about','abuse','main','data','example','jabber','legal','invite',
        'copyright','contact','board','feedback','support','anonymous','index',
        'inbox','payment','donate','calendar','dotfiles','billing','billings',
        'images','media','policy','manage','messages','mobile','official',
        'staging','development','staff','portal','forum','forums','pictures',
        'photos','status','finger','private','press','user','users','username',
        'usernames','sitemap','team','teams','account','accounts','chat','mail',
        'email','admin','admins','administrator','administrators','postmaster',
        'hostmaster','webmaster'
    ] 
    if re.compile(r"^[a-zA-Z0-9_]{4,31}$").match(value) is None:
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
