#!/usr/bin/env python
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
notes:
  - If you have multiple topics to modify, using the I(topics) option is much
    faster, as it can execute C(kafka-topics.sh) fewer times.
requirements:
  - C(kafka-topics.sh) must be installed on the host.
author: James Bowes
options:
  name:
    description:
      - The topic name to create or update
    aliases: [topic]
  partitions:
    description:
      - The number of partitions for I(name), or the default partitions for
        I(topics) if nothing is specified.
  replicas:
    description:
      - The replication factor for I(name), or the default replication factor
        for I(topics) if nothing is specified.
  topics:
    description:
      - A list of topic names to create or update (using the default
        I(partitions) and I(replicas)), or a list of dicts containing I(name),
        I(partitions), and I(replicas) values.
  zookeeper:
    description:
      - A I(ZooKeeper) connection string, as used by I(Kafka).
    required: true
  path:
    description:
      - Optional path to the directory containing C(kafka-topics.sh), if it is
        not in I(PATH).
"""

EXAMPLES = """
# Create a single topic
- kafka_topics: name=my-topic partitions=1 replicas=1 zookeeper=localhost:2181

# Increase the partition count of the above topic
- kafka_topics: name=my-topic partitions=2 replicas=1 zookeeper=localhost:2181

# Create and update multiple topics at once (faster!)
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
"""

import re
import collections

# Initialiize Ansible Module
# import module snippets
from ansible.module_utils.basic import *

def read_topics(kafka_topics, m):
    p = m.params

    cmd = "%s --zookeeper %s --describe" % (kafka_topics, p["zookeeper"])
    # If a single topic was given, it will be faster to only check it
    if p["topic"]:
        cmd += " --topic %s" % (p["topic"],)

    rc, out, err = m.run_command(cmd)
    if rc:
        m.fail_json(msg="listing topics failed: %s" % (err), stdout=out)

    topics = {}
    config_re = re.compile("^Topic:(?P<name>\S+)\s*"
                           "PartitionCount:(?P<partitions>\d+)\s*"
                           "ReplicationFactor:(?P<replicas>\d+)",
                           flags=re.MULTILINE)
    matches = config_re.finditer(out)
    for match in matches:
        topics[match.group("name")] = {
                "partitions": int(match.group("partitions")),
                "replicas": int(match.group("replicas")),
                }

    return topics


def execute_change(kafka_topics, m, state, topic, partitions, replicas):
    p = m.params

    cmd = "%s --zookeeper %s --%s --topic %s --partitions %d" % (kafka_topics,
            p["zookeeper"], state, topic, partitions)

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
            zookeeper=dict(required=True),
            topics=dict(default=None, type='list'),
            topic=dict(default=None, aliases=["name"]),
            partitions=dict(default=None, type="int"),
            replicas=dict(default=None, type="int"),
        ),
        required_one_of=[["topic", "topics"]],
        supports_check_mode=True,
    )

    changed = False

    p = module.params
    args = ["partitions", "replicas"]

    topics = {}
    if p["topic"]:
        for arg in args:
            if not p[arg]:
                module.fail_json("You must provide '%s' for a single topic" %
                        (arg,))
        topic_spec = {k: p[k] for k in args}
        topics[p["topic"]] = topic_spec
    else:
        for topic in p["topics"]:
            name = None
            if isinstance(topic, basestring):
                name = topic
                topics[name] = {
                        "partitions": p["partitions"],
                        "replicas": p["replicas"],
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
            if None in [spec["partitions"], p["replicas"]]:
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
    for name, spec in topics.items():
        # Does it already exist? if so, should we change
        # the partitions/replicas?
        if name in existing_topics:
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
                    altered[name] = spec
        else:
            created[name] = spec

    if altered or created:
        changed = True

    out = dict(changed=changed)
    msgs = []
    if created:
        msgs.append("CREATED: " + ", ".join([k for k in created.keys()]))
        out["created"] = created
    if altered:
        msgs.append("ALTERED: " + ", ".join([k for k in altered.keys()]))
        out["altered"] = altered
    if changed:
        out["msg"] = " ".join(msgs)

    if not module.check_mode:
        for name, spec in altered.items():
            execute_change(kafka_topics, module, "alter", name,
                    spec["partitions"], spec["replicas"])

        for name, spec in created.items():
            execute_change(kafka_topics, module, "create", name,
                    spec["partitions"], spec["replicas"])

    module.exit_json(**out)


if __name__ == "__main__":
    main()
