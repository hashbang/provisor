import os,sys
import re
import time

import pwd, grp, spwd
from provisor import Provisor

MIN_UID = 1001
EXCLUDED_UIDS = (65534,)


## Regexpts we use
valid_user = re.compile('[a-zA-Z][a-zA-Z0-9_]{3,31}')
valid_home = re.compile('/home/[a-zA-Z][a-zA-Z0-9_]{3,31}')
valid_pkey = re.compile('(ssh\-(rsa|dsa|ecdsa) [a-zA-Z0-9+/=]{180,5000})( .*$)?')
## Valid shells
valid_shells = []
for s in open("/etc/shells").readlines():
  if s.startswith('#'):
    continue
  valid_shells.append(s.rstrip())
valid_shells = set(valid_shells)
## The 'nowday' for the last change
nowday = int(time.time() / 86400)
## All the groups
allgroups = grp.getgrall()

def search_groups(member):
  supp = []
  for g in allgroups:
    if member in g.gr_mem:
      supp.append(g)
  return tuple(supp)


def main():
  prov = Provisor("change_this")
  allusers = pwd.getpwall()
  for u in allusers:
    ## Dont migrate users less than a specific value
    if u.pw_uid < MIN_UID or u.pw_uid in EXCLUDED_UIDS:
      continue

    ## Obtain the users details.
    try:
      s = spwd.getspnam(u.pw_name)
      g = grp.getgrnam(u.pw_name)
    except KeyError:
      sys.stderr.write("Cannot import {0} as cannot find entry in group or shadow database\n".format(u.pw_name))
      continue

    ## Obtain their pubkey.
    try:
      pubkey = None
      pkf = open("{0}/.ssh/authorized_keys".format(u.pw_dir))
      for p in pkf.readlines():
        if p.startswith('ssh'):
          pubkey = p
          break
      if not pubkey:
        sys.stderr.write("Unable to migrate '{0}' as the user has no valid public key\n".format(u.pw_name))
        continue
    except:
      sys.stderr.write("Unable to migrate '{0}' as the pubkey file was not accessible\n".format(u.pw_name))
      continue

    ## Time to validate some entries
    if not valid_user.match(u.pw_name):
      sys.stderr.write("The username '{0}' did not validate as the username is invalid\n".format(u.pw_name))
      continue
    if not valid_home.match(u.pw_dir):
      sys.stderr.write("The username '{0}' did not validate as the home directory {1} is invalid\n".format(u.pw_name, u.pw_dir))
      continue
    if not valid_pkey.match(pubkey):
      sys.stderr.write("The username '{0}' did not validate as the public key is invalid\n".format(u.pw_name))
      continue
    else:
      ## Reformat the pubkey to remove comments
      m = valid_pkey.match(pubkey)
      pubkey = m.group(1)
    if u.pw_shell not in valid_shells:
      sys.stderr.write("The username '{0}' did not validate as the shell '{1}' is invalid\n".format(u.pw_name, u.pw_shell))
      continue
    ## Validate shadow details..
    if s.sp_lstchg < 1000 or s.sp_lstchg > nowday:
      sys.stderr.write("The username '{0}' did not validate as the users shadow last change field is invalid\n".format(u.pw_name))
      continue
    if s.sp_min < 0 or s.sp_min > 99999:
      sys.stderr.write("The username '{0}' did not validate as the users shadow minimum password change field is invalid ({1})\n".format(u.pw_name, s.sp_min))
      continue
    if s.sp_max < 0 or s.sp_max > 99999:
      sys.stderr.write("The username '{0}' did not validate as the users shadow maximum password change field is invalid ({1})\n".format(u.pw_name, s.sp_max))
      continue
    if s.sp_warn < 0 or s.sp_warn > 99999:
      sys.stderr.write("The username '{0}' did not validate as the users shadow warning age field is invalid ({1})\n".format(u.pw_name, s.sp_warn))
      continue
    if s.sp_inact < -1 or s.sp_inact > 99999:
      sys.stderr.write("The username '{0}' did not validate as the users shadow inactive age field is invalid ({1})\n".format(u.pw_name, s.sp_inact))
      continue
    if s.sp_expire < -1 or s.sp_expire > 99999:
      sys.stderr.write("The username '{0}' did not validate as the users shadow expire age field is invalid ({1})\n".format(u.pw_name, s.sp_expire))
      continue

    ## If the user exists mark as such, we treat differently.
    if prov.user_exists(u.pw_name):
      prov.modify_user(u.pw_name, pubkey=pubkey, hostname='va1.hashbang.sh', shell=u.pw_shell, homedir=u.pw_dir, raw_passwd=s.sp_pwd, uid=u.pw_uid,
                       gid=u.pw_gid, lastchange=s.sp_lstchg, nextchange=s.sp_min, warning=s.sp_warn)
    else:
      prov.add_user(u.pw_name, pubkey, 'va1.hashbang.sh', shell=u.pw_shell, homedir=u.pw_dir, raw_passwd=s.sp_pwd, uid=u.pw_uid, 
                    gid=u.pw_gid, lastchange=s.sp_lstchg, nextchange=s.sp_min, warning=s.sp_warn)
    ## Same for group
    if not prov.group_exists(g.gr_name):
      prov.add_group(g.gr_name, gid=u.pw_uid)

    ## Supplementary groups
    for g in search_groups(u.pw_name):
      if not prov.group_exists(g.gr_name):
        prov.add_group(g.gr_name, gid=g.gr_gid)
      if not prov.is_group_member(g.gr_name, u.pw_name):
        prov.add_group_member(g.gr_name, u.pw_name)
  

if __name__ == "__main__":
  main() 

