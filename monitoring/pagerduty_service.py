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
module: pagerduty_service
short_description: Manipulate PagerDuty services
description:
  - Create and modify I(PagerDuty) services.
author: James Bowes
options:
  name:
    description:
      - The unique name of the service.
    required: true
  domain:
    description:
      - PagerDuty unique subdomain.
    required: true
  token:
    description:
      - A PagerDuty API token.
    required: true
  description:
    description:
      - A optional description of the service.
    required: false
  escalation_policy_id:
    description:
      - The unique ID of the escalation_policy to associate with this service.
        Either C(escalation_policy) or C(escalation_policy_id) are required.
    required: false
  escalation_policy:
    description:
      - The name of the escalation_policy to associate with this service.
        Either C(escalation_policy) or C(escalation_policy_id) are required.
    required: false
  type:
    description:
      - The type of the service.
    required: false
    default: generic_events_api
    choices:
      - generic_events_api
      - generic_email
      - keynote
      - nagios
      - pingdom
      - sql_monitor
  service_key:
    description:
      - A unique key for sending alerts to this service.
      - For a service C(type) that uses email (I(generic_email), I(keynote),
        I(pingdom), I(sql_monitor)), the service key is required and must be a
        unique value for the user part of an email in your PagerDuty domain.
        It can be changed.
      - For API type services (I(generic_events_api), I(nagios)), this value is
        not required. If present, it must be I(regenerate), indicating that
        PagerDuty should generate a new random service_key for this service.
    required: false
  ack_timeout:
    description:
      - The time in seconds before acknowledged incidents in this service
        become triggered again. Set to I(disabled) to not timeout acknowledged
        incidents.
    required: false
    default: disabled
  resolve_timeout:
    description:
      - The time in seconds before incidents in this service will auto-resolve.
        Set to I(disabled) to never auto-resolve incidents.
    required: false
    default: disabled
  state:
    description:
      - Indicates the desired service state C(present) indicates the service
        should exist with the given parameters. C(absent) the service should
        not exist. C(disabled) indicates the service should exist, but be
        disabled, and not trigger alerts. If C(disabled), one of I(requester)
        or I(requester_id) must be provided.
    required: false
    default: present
    choices: [ "present", "absent", "disabled" ]
  requester_id:
    description:
      - The unique ID of the user requesting a service to be disabled.
        See I(state) for more details.
    required: false
  requester:
    description:
      - The email of the user requesting a service to be disabled.
        See I(state) for more details.
    required: false
  webhooks:
    description:
      - An optional list of webhooks to call when incidents occur and change in
        this service.
      - Each webhook must be a dictionary containing C(name) and C(url) keys.
    required: false
"""

EXAMPLES = """
# Create a new service in PagerDuty
- pagerduty_service:
    name: Production Alerts
    description: Alerts triggered from production.
    escalation_policy: Default
    domain: mycompany
    token: abcxzy

# Disable a service
- pagerduty_service:
    name: Production Alerts
    description: Alerts triggered from production.
    escalation_policy: Default
    domain: mycompany
    token: abcxzy
    state: disabled
    requester: me@mycompany.com

# Create a service with webhooks
- pagerduty_service:
    name: Production Alerts
    description: Alerts triggered from production.
    escalation_policy_id: BHDE11T
    domain: mycompany
    token: abcxzy
    webhooks:
      - name: Slack
        url: http://somehook.com/some-id

# Prompt PagerDuty to regenerate a service key
- pagerduty_service:
    name: Production Alerts
    description: Alerts triggered from production.
    escalation_policy_id: BHDE11T
    domain: mycompany
    token: abcxzy
    service_key: regenerate

# Create a service that will retrigger incidents after 30 minutes,
# and auto-resolve after 4 hours.
- pagerduty_service:
    name: Production Alerts
    description: Alerts triggered from production.
    escalation_policy_id: BHDE11T
    domain: mycompany
    token: abcxzy
    ack_timeout: 1800
    resolve_timeout: 14400
"""

import urllib

EMAIL_TYPES = ["generic_email", "pingdom", "keynote", "sql_monitor"]

def fetch(module, method, path, data=None):
    p = module.params

    url = "https://%s.pagerduty.com/api/v1/" % p["domain"]
    url += path
    auth = "token=%s" % p["token"]
    response, info = fetch_url(module, url, method=method, data=data,
                               headers={"Content-type": "application/json",
                                        "Authorization": "Token %s" % auth})

    if info['status'] not in (200, 201, 204):
        module.fail_json(msg=info['msg'])

    body = response.read()

    if body:
        return json.loads(body)
    else:
        return {}


def get_service(module):
    p = module.params
    response = fetch(module, "GET", "services?" + urllib.urlencode({
        "query": p["name"],
        "include[]": "escalation_policy",
    }))
    services = response.get("services", [])
    return next((x for x in services if x.get("name") == p["name"]), {})


def create_service(module):
    p = module.params

    service = {
        "name": p["name"],
        "escalation_policy_id": p["escalation_policy_id"],
        "type": p["type"]
    }

    if p["description"]:
        service["description"] = p["description"]
    if p["resolve_timeout"]:
        service["auto_resolve_timeout"] = p["resolve_timeout"]
    if p["ack_timeout"]:
        service["acknowledgement_timeout"] = p["ack_timeout"]
    if p["service_key"]:
        service["service_key"] = p["service_key"]

    response = fetch(module, "POST", "services",
                     json.dumps({"service": service}))
    service = response.get("service", {})
    service["escalation_policy"] = {"id": p["escalation_policy_id"]}
    return service


def delete_service(module, service):
    fetch(module, "DELETE", "services/%s" % service["id"])


def get_webhooks(module, service):
    response = fetch(module, "GET", "webhooks?" + urllib.urlencode({
        "webhook_object[type]": "service",
        "webhook_object[id]": service["id"]
    }))
    return response.get("webhooks", [])


def add_webhook(module, service, webhook):
    data = {
        "webhook": {
            "name": webhook["name"],
            "url": webhook["url"],
            "webhook_object": {
                "id": service["id"],
                "type": "service",
                "object": {
                    "service": {
                        "id": service["id"],
                        "type": "service"
                    }
                }
            }
        }
    }

    response = fetch(module, "POST", "webhooks", json.dumps(data))
    return response.get("webhook", {})


def update_webhook(module, service, webhook):
    response = fetch(module, "PUT", "webhooks/%s" % webhook["id"],
                     json.dumps(webhook))
    return response.get("webhook", {})


def delete_webhook(module, service, webhook):
    fetch(module, "DELETE", "webhooks/%s" % webhook["id"])


def get_service_key(p):
    if p["type"] not in EMAIL_TYPES:
        return "*NEW KEY*"
    else:
        return "%s@%s.pagerduty.com" % (p["service_key"], p["domain"])


def create_or_delete_service(module, service):
    p = module.params

    changed = False

    if p["state"] in ["present", "disabled"] and not service:
        changed = True
        if not module.check_mode:
            # read service here, for use with setting status
            # and configuring webhooks
            service = create_service(module)
        else:
            service_key = get_service_key(p)
            module.exit_json(changed=changed, service_key=service_key)
    elif p["state"] == "absent":
        if service:
            changed = True
            # Delete service
            if not module.check_mode:
                delete_service(module, service)
            module.exit_json(changed=changed)
        else:
            module.exit_json(changed=changed)
    elif p["type"] != service["type"]:
        changed = True
        if not module.check_mode:
            delete_service(module, service)
            service = create_service(module)
        else:
            service_key = get_service_key(p)
            module.exit_json(changed=changed, service_key=service_key)

    return changed, service


def update_service(module, service):
    p = module.params
    changed = False
    new_values = {}

    if p["description"] is not None and ("description" not in service or
            p["description"] != service["description"]):
        changed = True
        new_values["description"] = p["description"]

    if p["escalation_policy_id"] != service["escalation_policy"]["id"]:
        changed = True
        new_values["escalation_policy_id"] = p["escalation_policy_id"]

    if p["ack_timeout"] != service["acknowledgement_timeout"]:
        changed = True
        new_values["acknowledgement_timeout"] = p["ack_timeout"]

    if p["resolve_timeout"] != service["auto_resolve_timeout"]:
        changed = True
        new_values["auto_resolve_timeout"] = p["resolve_timeout"]

    if p["service_key"] and service["type"] in EMAIL_TYPES and \
            "%s@%s.pagerduty.com" % (p["service_key"],
                    p["domain"]) != service["service_key"]:
        changed = True
        new_values["service_key"] = p["service_key"]

    if changed and not module.check_mode:
        response = fetch(module, "PUT", "services/%s" % service["id"],
                json.dumps({"service": new_values}))

    service.update(new_values)

    if "service_key" in new_values and service["type"] in EMAIL_TYPES:
        service["service_key"] += "@%s.pagerduty.com" % p["domain"]

    return changed


def regenerate_key(module, service):
    p = module.params
    changed = False

    if service["type"] in EMAIL_TYPES or not p["service_key"]:
        return changed

    changed = True
    if not module.check_mode:
        response = fetch(module, "POST",
                         "services/%s/regenerate_key" % service["id"])
        service["service_key"] = response["service"]["service_key"]
    else:
        service["service_key"] = "*NEW KEY*"

    return changed

def disable_or_enable_service(module, service):
    p = module.params
    changed = False

    if service["status"] == "disabled" and p["state"] != "disabled":
        changed = True
        if not module.check_mode:
            fetch(module, "PUT", "services/%s/enable" % service["id"])
    elif p["state"] == "disabled" and service["status"] != "disabled":
        changed = True
        if not module.check_mode:
            if not p["requester_id"]:
                p["requester_id"] = get_user_id(module, p["requester"])
            data = json.dumps({"requester_id": p["requester_id"]})
            fetch(module, "PUT", "services/%s/disable" % service["id"], data)

    return changed


def disabled_or_int(module, key):
    p = module.params
    if p[key] == "disabled":
        return None

    try:
        return int(p[key])
    except:
        module.fail_json(msg="'%s' must be an integer, or 'disabled'" % key)


def get_user_id(module, email):
    response = fetch(module, "GET", "users?query=%s" % urllib.quote(email))

    if "users" not in response:
        module.fail_json(msg="Bad response from pagerduty")

    users = response["users"]

    if len(users) == 0:
        module.fail_json(msg="No matching users for '%s'" % email)
    if len(users) > 1:
        module.fail_json(msg="More than one matching user for '%s'" % email)

    return users[0]["id"]


def get_escalation_policy_id(module, policy):
    response = fetch(module, "GET", "escalation_policies?query=%s" %
            urllib.quote(policy))

    if "escalation_policies" not in response:
        module.fail_json(msg="Bad response from pagerduty")

    policies = response["escalation_policies"]

    if len(policies) == 0:
        module.fail_json(msg="No matching policies for '%s'" % policy)
    if len(policies) > 1:
        module.fail_json(msg="More than one matching policy for '%s'" % policy)

    return policies[0]["id"]


def modify_webhooks(module, service):
    p = module.params
    changed = False

    if not p["webhooks"]:
        return changed

    webhooks = get_webhooks(module, service)
    old_hooks = {}
    for webhook in webhooks:
        old_hooks[webhook["name"]] = webhook

    new_hooks = {}
    for webhook in p["webhooks"]:
        new_hooks[webhook["name"]] = webhook

    added_webhooks = []
    changed_webhooks = []
    deleted_webhooks = []
    for webhook in p["webhooks"]:
        if webhook["name"] not in old_hooks:
            added_webhooks.append(webhook)
        elif webhook["name"] in old_hooks and \
                webhook["url"] != old_hooks[webhook["name"]]["url"]:
            updated_hook = old_hooks[webhook["name"]]
            updated_hook["url"] = webhook["url"]
            changed_webhooks.append(updated_hook)
    for webhook in webhooks:
        if webhook["name"] not in new_hooks:
            deleted_webhooks.append(webhook)

    if added_webhooks or changed_webhooks or deleted_webhooks:
        changed = True

        if not module.check_mode:
            for webhook in deleted_webhooks:
                delete_webhook(module, service, webhook)
            for webhook in changed_webhooks:
                update_webhook(module, service, webhook)
            for webhook in added_webhooks:
                add_webhook(module, service, webhook)

    return changed


def main():
    """
    Main execution block and ansible boiler plate
    """

    module = AnsibleModule(
        argument_spec = dict(
            name=dict(required=True),
            domain=dict(required=True),
            token=dict(required=True),
            description=dict(required=False),
            escalation_policy_id=dict(),
            escalation_policy=dict(),
            ack_timeout=dict(required=False, default="disabled"),
            resolve_timeout=dict(required=False, default="disabled"),
            service_key=dict(required=False),
            type=dict(default="generic_events_api",
                      choices=["generic_email", "generic_events_api", "keynote",
                               "nagios", "pingdom", "sql_monitor"]),
            state=dict(default="present",
                       choices=["present", "absent", "disabled"]),
            requester_id=dict(required=False),
            requester=dict(required=False),
            webhooks=dict(required=False, type="list"),
        ),
        mutually_exclusive=[["requester_id", "requester"],
                            ["escalation_policy_id", "escalation_policy"]],
        required_one_of=[["escalation_policy_id", "escalation_policy"]],
        supports_check_mode=True,
    )
    p = module.params

    if p["type"] not in EMAIL_TYPES and p["service_key"] and \
            p["service_key"] != "regenerate":
        module.fail_json(msg="You can only 'regenerate' service keys with "
                             "type '%s'" % p["type"])
    elif p["type"] in EMAIL_TYPES and not p["service_key"]:
        module.fail_json(msg="service_key is required with type '%s'" %
                p["type"])


    p["ack_timeout"] = disabled_or_int(module, "ack_timeout")
    p["resolve_timeout"] = disabled_or_int(module, "resolve_timeout")

    if not p["escalation_policy_id"]:
        p["escalation_policy_id"] = get_escalation_policy_id(module,
                p["escalation_policy"])

    service = get_service(module)

    changed, service = create_or_delete_service(module, service)
    changed |= update_service(module, service)
    changed |= regenerate_key(module, service)
    changed |= disable_or_enable_service(module, service)
    changed |= modify_webhooks(module, service)

    module.exit_json(changed=changed, service_key=service["service_key"])


# Initialiize Ansible Module
# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *


if __name__ == "__main__":
    main()
