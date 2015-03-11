#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, James Bowes <jbowes@repl.ca>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = """
---
module: zookeeper
short_description: Manipulate ZooKeeper keys
description:
  - Create and modify I(ZooKeeper) keys.
requirements:
  - C(kazoo)
author: James Bowes
options:
  name:
    description:
      - The key to manipulate.
    aliases: [key, path]
    required: true
  value:
    description:
      - An optional value to set for the key.
  state:
    description:
      - Indicates the desired key state C(present) indicates the key should
        exist with the given value, or be empty if no value is provided.
        C(absent) indicates the path should not exist.
    default: present
    choices: ["present", "absent"]
  acls:
    description:
      - A single ACL, or list of ACLs for the node, of the form
        'scheme:identity:perms'.
      - Valid schemes are 'world', 'digest', 'userpass', 'ip'.
      - Valid perms are 'c', 'r', 'w', 'd', 'a'.
  exclusive:
    description:
      - Whether to remove all other non-specified ACLs from the key.
    default: no
    choices: ["yes", "no"]
  login_host:
    description:
      - The host running I(ZooKeeper).
    default: localhost
  login_port:
    description:
      - The port to connect to.
    default: 2181
  login_user:
    description:
      - Optional username for authentication.
  login_password:
    description:
      - Optional password for authentication.
"""

EXAMPLES = """
# Ensure a key exists and is empty
- zookeeper: name=/my/key

# Ensure a key exists with a value
- zookeeper: name=/my/other/key value="has a nice value"

# Ensure a key does not exist
- zookeeper: name=/make/sure/this/is/gone state=absent

# Allow user1 to perform all actions on a key
- zookeeper:
    name: /key
    value: "something"
    acls:
      - "userpass:user1:password:crwda"

# Grant admin permissions on a key to user1.
# Allow user2 to create and delete child keys.
# Allow everyone to read the key and its children.
- zookeeper:
    name: /key
    value: "something"
    acls:
      - "digest:user1:bYeZNFxkmtQrhcuNivU587R4lRg=:a"
      - "userpass:user2:password:cd"
      - "world:anyone:r"
"""

import sys

# Prevent kazoo logging from messing up our output.
import logging
logging.basicConfig()
logging.getLogger("kazoo").propagate = False

try:
    from kazoo.client import KazooClient
    from kazoo.exceptions import NoAuthError, NoNodeError, ZookeeperError
    from kazoo.security import make_acl, make_digest_acl_credential
except ImportError:
    print "failed=True msg='kazoo is required for this module. "\
          "see https://kazoo.readthedocs.org/en/latest/install.html'"
    sys.exit(1)

# Initialiize Ansible Module
# import module snippets
from ansible.module_utils.basic import *


def remove_op(zk, key, check_mode):
    """
    Ensure a key does not exist.
    """
    changed = False
    if check_mode:
        changed = not zk.exists(key)
    else:
        try:
            zk.delete(key)
            changed = True
        except NoNodeError:
            pass

    return changed


def set_op(zk, key, value, acls, exclusive, check_mode):
    """
    Ensure a key exists, and has the provided value.
    """
    changed = False
    acl_changed = False
    exists = True

    try:
        existing, _ = zk.get(key)
        changed = existing != value
        existing_acls, _ = zk.get_acls(key)
        existing_acls = set(existing_acls)
        if exclusive:
            if existing_acls != acls:
                acl_changed = True
        elif not existing_acls.issuperset(acls):
            acl_changed = True
            acls = existing_acls.union(acls)
    except NoNodeError:
        exists = False
        changed = True

    if not check_mode:
        acls = list(acls)
        if not exists:
            zk.create(key, value, acl=acls, makepath=True)
        else:
            if changed:
                zk.set(key, value)
            if acl_changed:
                zk.set_acls(key, acls=acls)

    return changed or acl_changed


def build_acls(m, acl_strs):
    acls = set()
    for acl_str in acl_strs:
        parts = acl_str.split(':')
        if len(parts) < 3:
            m.fail_json(msg="ACLs must be of the form 'scheme:identity:perms'")

        scheme = parts[0].lower()
        perms = parts[-1].lower()
        identity = ":".join(parts[1:-1])

        for perm in perms:
            if perm not in ['c', 'r', 'w', 'd', 'a']:
                m.fail_json(msg="ACL perms must be a subset of 'crwda'")

        perms = dict(
                create='c' in perms,
                read='r' in perms,
                write='w' in perms,
                delete='d' in perms,
                admin='a' in perms,
                )

        acl = None
        if scheme == "world":
            identity = 'anyone'
        elif scheme == "digest":
            userpass = identity.split(":")
            if len(userpass) != 2:
                m.fail_json(msg="digest ACL identity must be 'user:digest'")
        elif scheme == "userpass":
            scheme = "digest"
            userpass = identity.split(":")
            if len(userpass) != 2:
                m.fail_json(msg="userpass ACL identity must be 'user:pass'")
            identity = make_digest_acl_credential(*userpass)
        elif scheme != "ip":
            m.fail_json(msg="ACL scheme must be one of 'world', 'digest', "
                        "'userpass', 'ip'")

        acl = make_acl(scheme, identity, **perms)
        acls.add(acl)

    return acls


def main():
    """
    Main execution block and ansible boiler plate
    """

    module = AnsibleModule(
        argument_spec = dict(
            name=dict(required=True, aliases=["key", "path"]),
            value=dict(default=b""),
            state=dict(default="present", choices=["present", "absent"]),
            login_host=dict(default="localhost"),
            login_port=dict(default=2181, type="int"),
            login_user=dict(default=None),
            login_password=dict(default=None),
            acls=dict(default=[], aliases=["acl"]),
            exclusive=dict(default=False, type="bool"),
        ),
        required_together=[["login_user", "login_password"]],
        supports_check_mode=True,
    )
    p = module.params

    changed = False
    should_exist = p["state"] == "present"
    connection_string = "%s:%d" % (p["login_host"], p["login_port"])

    auth = None
    if p["login_user"]:
        auth = [("digest", "%s:%s" % (p["login_user"], p["login_password"]))]

    try:
        zk = KazooClient(hosts=connection_string, auth_data=auth)
        zk.start()
    except ZookeeperError as e:
        module.fail_json(msg="Failed to connect to ZooKeeper at '%s'" % (
            connection_string), stderr=str(e))

    try:
        if not should_exist:
            changed = remove_op(zk, p["name"], module.check_mode)
        else:
            if isinstance(p["acls"], basestring):
                p["acls"] = [p["acls"]]
            acls = build_acls(module, p["acls"])
            changed = set_op(zk, p["name"], p["value"], acls, p["exclusive"],
                    module.check_mode)
    except NoAuthError as e:
        module.fail_json(msg="Permission denied on key '%s'" %(p["name"],),
                stderr=str(e.code))
    except ZookeeperError as e:
        module.fail_json(msg="Error manipulating key '%s'" % (p["name"],),
                stderr=str(e.code))

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
