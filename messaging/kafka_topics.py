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
module: kafka_topics
short_description: Create and modify Kafka topics.
description:
  - Create and modify I(Kafka) topics.
requirements:
  - C(kafka-topics.sh) must be installed on the host.
author: James Bowes
options:
  topics:
    description:
      - A list of topic names to create or update (using the default
        I(partitions), I(replicas), and I(config)), or a list of dicts containing I(name),
        I(partitions), I(replicas), and I(config) values.
      - I(config) is a comma separated list of valid key-value configs for the given topic.
    required: True
  partitions:
    description:
      - The default partitions for I(topics) if nothing is specified.
  replicas:
    description:
      - The default replication factor for I(topics) if nothing is specified.
  config:
    description:
      - The default per-topic config for I(topics) if nothing is specified.
  zookeeper:
    description:
      - A I(ZooKeeper) connection string, as used by I(Kafka).
    default: localhost:2181
  state:
    description:
      - The desired state for all topics.
      - To remove a topic, you must have a recent enough I(Kafka) (> 0.8.2).
    default: present
    choices: ["present", "absent"]
  path:
    description:
      - Optional path to the directory containing C(kafka-topics.sh), if it is
        not in I(PATH).
"""

EXAMPLES = """
# Create and update multiple topics
- kafka_topics:
    topics: [my-topic, my-other-topic]
    partitions: 1
    replicas: 1
    zookeeper: localhost:2181

# Create and update multiple topics with specific partitions and replicas
- kafka_topics:
    topics:
      - name: my-topic
        partitions: 2
        replicas: 1
      - name: my-other-topic
        partitions: 1
        replicas: 3
    zookeeper: localhost:2181

# Mix overrides and defaults
- kafka_topics:
    topics:
      - my-topic
      - name: my-other-topic
      - name: my-third-topic
        partitions: 12
        replicas: 3
    partitions: 1
    replicas: 2
    zookeeper: localhost:2181

# Remove some topics
- kafka_topics:
    topics:
      - remove-this
      - and-this
"""

import re
import collections

# Initialiize Ansible Module
# import module snippets
from ansible.module_utils.basic import *


def config_dict(config_str):
    if isinstance(config_str, collections.Mapping):
        return config_str
    return dict(p.split("=") for p in config_str.split(",") if "=" in p)


def read_topics(kafka_topics, m):
    p = m.params

    cmd = "%s --zookeeper %s --describe" % (kafka_topics, p["zookeeper"])
    rc, out, err = m.run_command(cmd)
    if rc:
        m.fail_json(msg="listing topics failed: %s" % (err), stdout=out)

    topics = {}
    config_re = re.compile("^Topic:(?P<name>\S+)\s*"
                           "PartitionCount:(?P<partitions>\d+)\s*"
                           "ReplicationFactor:(?P<replicas>\d+)\s*"
                           "Configs:(?P<config>\S*)",
                           flags=re.MULTILINE)
    matches = config_re.finditer(out)
    for match in matches:
        topics[match.group("name")] = {
                "partitions": int(match.group("partitions")),
                "replicas": int(match.group("replicas")),
                "config": config_dict(match.group("config")),
                }

    return topics


def execute_change(kafka_topics, m, state, topic, partitions, replicas,
        alter_config={}, remove_config={}):
    p = m.params

    cmd = "%s --zookeeper %s --%s --topic %s" % (kafka_topics, p["zookeeper"],
            state, topic)

    if state != "delete":
        cmd += " --partitions %d" % (partitions,)

        for k, v in alter_config.items():
            cmd += " --config %s=%s" % (k, v)
        for k in remove_config:
            cmd += " --delete-config %s" % (k,)

    if state == "create":
        cmd += " --replication-factor %d" % (replicas,)

    rc, out, err = m.run_command(cmd)
    if rc:
        m.fail_json(msg="%s of topic '%s' failed: %s" % (state, topic, err),
                stdout=out)


def main():
    """
    Main execution block and ansible boiler plate
    """

    module = AnsibleModule(
        argument_spec = dict(
            path=dict(default=None),
            zookeeper=dict(default="localhost:2181"),
            topics=dict(default=None, required=True, type="list"),
            partitions=dict(default=None, type="int"),
            replicas=dict(default=None, type="int"),
            config=dict(default=""),
            state=dict(default="present", choices=["present", "absent"]),
        ),
        supports_check_mode=True,
    )

    changed = False

    p = module.params
    args = ["partitions", "replicas", "config"]

    topics = {}
    for topic in p["topics"]:
        name = None
        if isinstance(topic, basestring):
            name = topic
            topics[name] = {
                    "partitions": p["partitions"],
                    "replicas": p["replicas"],
                    "config": p["config"],
                    }
        elif isinstance(topic, collections.Mapping):
            name = topic.get("name")
            name = name if name else topic.get("topic")
            if name is None:
                module.fail_json(msg="You must provide a topic name")

            topics[name] = {k: topic.get(k) if topic.get(k) else p[k]
                    for k in args}
        else:
            module.fail_json(msg="'topics' must be a list of strings or "
                    "dicts")

        spec = topics[name]
        spec["config"] = config_dict(spec["config"])
        if None in [spec["partitions"], p["replicas"]] and \
                p["state"] != "absent":
                module.fail_json(msg="You must provide partitions and "
                        "replicas for topic '%s' without "
                        "overrides" % (name))

    kafka_topics = module.get_bin_path("kafka-topics.sh",
            opt_dirs=[p["path"]], required=True)
    existing_topics = read_topics(kafka_topics, module)

    # Figure out what topics need to be changed up front, in case we're being
    # Asked to decrease the replicas, which isn't possible
    altered = {}
    created = {}
    deleted = []
    for name, spec in topics.items():
        if name in existing_topics and p["state"] == "absent":
            deleted.append(name)
        elif name in existing_topics:
            # Does it already exist? if so, should we change
            # the partitions/replicas?
            existing = existing_topics[name]
            for k in args:
                if k == "partitions" and spec[k] < existing[k]:
                    msg = "Cannot reduce partitions on '%s' %d => %d" % (
                            name, existing[k], spec[k])
                    module.fail_json(msg=msg)
                elif k == "replicas" and spec[k] != existing[k]:
                    msg = "Cannot change replicas on '%s' %d => %d" % (
                            name, existing[k], spec[k])
                    module.fail_json(msg=msg)

                if spec[k] != existing[k]:
                    if k == "config":
                        target_config = spec["config"]
                        spec["config"] = dict((k, v) for k, v
                                in target_config.items() \
                                if v != existing["config"].get(k))
                        spec["config_deleted"] = [k for k
                                in existing["config"] if k not in target_config]

                    altered[name] = spec
        elif p["state"] != "absent":
            created[name] = spec

    if altered or created or deleted:
        changed = True

    out = dict(changed=changed)
    msgs = []
    if created:
        msgs.append("CREATED: " + ", ".join([k for k in created.keys()]))
        out["created"] = created
    if altered:
        msgs.append("ALTERED: " + ", ".join([k for k in altered.keys()]))
        out["altered"] = altered
    if deleted:
        msgs.append("DELETED: " + ", ".join([k for k in deleted]))
        out["deleted"] = deleted

    if changed:
        out["msg"] = " ".join(msgs)

    if not module.check_mode:
        for name, spec in altered.items():
            execute_change(kafka_topics, module, "alter", name,
                    spec["partitions"], spec["replicas"],
                    spec["config"], spec.get("config_deleted", []))

        for name, spec in created.items():
            execute_change(kafka_topics, module, "create", name,
                    spec["partitions"], spec["replicas"],
                    spec["config"])

        for name in deleted:
            execute_change(kafka_topics, module, "delete", name, None, None)

    module.exit_json(**out)


if __name__ == "__main__":
    main()
