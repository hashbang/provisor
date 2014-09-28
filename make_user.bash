#!/bin/bash
set -e

trap cleanup EXIT

# Maybe flocking this script will help prevent some racing

# 1. Create a new user
# 2. Input the SSH Key for said user into the authorized keys file
# 3. Set users quota

THEUSER=$1
KEYHEADER=$2
KEYTEXT=$3
ERROR=""

TMPKEY=$(/usr/bin/mktemp "/tmp/tmpkey.XXXXXXXX")

function cleanup
{
  ## Try to roll back on an error
  if [ -z "${ERROR}" -a -n "${THEUSER}" ]; then
    /usr/bin/getent passwd "${THEUSER}" >"/dev/null" && /sbin/userdel -r -f "${THEUSER}"
  fi

  if [ -n "${TMPKEY}" -a -f "${TMPKEY}" ]; then
    rm -f "${TMPKEY}"
  fi
}

if [ -z "$1" -o -z "$2" -o "$3" ]; then
  exit 1
fi

## Validate the given username
if ! [[ ${THEUSER} =~ ^[a-zA-Z0-9_]{4,48}$ ]]; then
  echo "Invalid username" >&2
  exit 1
fi

## Validate the given key
if ! [[ ${KEYHEADER} =~ ^ssh-(rsa|dsa)$ ]]; then 
  echo "Invalid key" >&2
  exit 1
fi

if ! [[ ${KEYTEXT} =~ ^[a-zA-Z0-9+/=]{64,2048}$ ]]; then
  echo "Invalid key">&2
  exit 1
fi

## Dump the key file somewhere safe
echo "${KEYHEADER} ${KEYTEXT}" >"${TMPKEY}"

## Determine if the user already exists.
if [ -e "/home/${THEUSER}" ]; then
  echo "This user already exists" >&2
  ERROR="no"
  exit 1
fi

## Create the user
/sbin/useradd -G "users" -m "${THEUSER}" -s "/bin/bash"

## Make the authorized keys bit
/bin/mkdir -m 700 "/home/${THEUSER}/.ssh"
/bin/chown "${THEUSER}:users" "/home/${THEUSER}/.ssh"

## Move the key into the users ssh authorized keys. Note move is important to prevent a race.
/bin/chown "${THEUSER}:users" "${TMPKEY}"
/bin/chmod "600" "${TMPKEY}" 
/bin/mv "${TMPKEY}" "/home/${THEUSER}/.ssh/authorized_keys"

## Set the users quota.
/usr/sbin/setquota -u "${THEUSER}" "976563" "1220703" "0" "0" -a "/dev/vda1"

## Create the Public directory and/or fix the permissions.

if [ ! -f "/home/${THEUSER}/Public" ]; then
  mkdir "/home/${THEUSER}/Public"
fi

chown "${THEUSER}:www-data" "/home/${THEUSER}/Public"
chmod 755 "/home/${THEUSER}/Public"

ERROR="no"
exit 0
