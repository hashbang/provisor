# Provisor #

Python library for provisioning and managing Linux users and SSH Public Keys across one or more servers via a central LDAP database.

## Dependencies ##

  * Python 2.7+
  * Running OpenLDAP server

## Setup ##

1. Setup base schema

    ```bash
    ldapmodify \
      -h ldap.example.com \
      -D "cn=admin,dc=example,dc=com" \
      -w somepass \
      -a ldif/base.ldif
    ```

2. Install library

    ```bash
    pip install provisor
   ```

## Usage ##

TODO
