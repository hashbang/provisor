# Provisor #

Python library for provisioning and managing Linux users and SSH Public Keys across one or more servers via a central LDAP database.

## Dependencies ##

  * Python 2.7+
  * Running OpenLDAP server

## Setup ##

1. Setup LDAP schema

    ```bash
    ldapmodify \
      -h ldap.example.com \
      -D "cn=admin,cn=config" \
      -w ROOT_PASS \
      -a ldif/schema.ldif
    ```

2. Setup LDAP Units

    ```bash
    ldapmodify \
      -h ldap.example.com \
      -D "cn=admin,dc=example,dc=com" \
      -w ADMIN_PASS \
      -a ldif/base.ldif
    ```


3. Install library

    ```bash
    pip install provisor
   ```

## Usage ##

TODO
