#!/usr/bin/python
# -*- coding: UTF-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: postconf

short_description: Configure postfix through postconf

version_added: "2.4"

description:
    - "This module sets/updates the Postfix MTA main configuration file"

options:
    config:
        description:
            - A dictionary of 'name: value' or 'name__operation: value' pairs, see example
        required: true

author:
    - Henryk Plötz (@henryk)
'''

EXAMPLES = '''
# Pass in a message
- name: Test with a message
  my_new_test_module:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_new_test_module:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_new_test_module:
    name: fail me
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import subprocess

def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        config=dict(type='dict', required=True),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        old_values = {},
        new_values = {},
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    for key_operation, value in module.params['config'].items():
        command_parts = key_operation.rsplit("__", 1)
        key = command_parts[0]

        if len(command_parts) < 2:
            operation = "set"
        else:
            operation = command_parts[1]

        if not operation in ("set", "append", "prepend"):
            module.fail_json(msg="Operation '%s' requested by key '%s' is not one of set, append, prepend." % (operation, key_operation), **result)

        if module.check_mode and key in result['new_values']:
            old_value = result['new_values'][key]
        else:
            old_value = subprocess.check_output(["postconf", "-h", key]).strip()
        
        result["old_values"].setdefault(key, old_value)

        if operation == "set":
            new_value = value.strip()
        elif operation in ("append", "prepend"):
            if old_value:
                values = old_value.split(",")
                values = [e.strip() for e in values]
            else:
                values = []

            if isinstance(value, (list, tuple)):
                value_list = value
            else:
                value_list = (value, )

            for value in value_list:
                value = value.strip()

                if not value in values:
                    if operation == "append":
                        values.append(value)
                    elif operation == "prepend":
                        values.push(value, 0)

            new_value = ",  ".join(values)

        if new_value != old_value:
            result['changed'] = True
            result["new_values"][key] = new_value
            if not module.check_mode:
                subprocess.check_call(["postconf", "-e", "%s=%s" % (key, new_value)])

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
