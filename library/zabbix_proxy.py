#!/usr/bin/python
# -*- coding: utf-8 -*-
## Based on https://github.com/dj-wasabi/ansible/blob/7d17c1692db6e346ecefdaac27ef5cd5e5e8fa3f/lib/ansible/modules/monitoring/zabbix_proxy.py
## Via https://github.com/ansible/ansible/pull/20053
## Modified for proxy use

# (c) 2013-2014, Epic Games, Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: zabbix_proxy
short_description: Zabbix proxy creates/updates/deletes
description:
   - This module allows you to create, modify and delete Zabbix proxy entries
version_added: "2.4"
author:
    - "(@cove)"
    - "Tony Minfei Ding"
    - "Harrison Gu (@harrisongu)"
    - "Werner Dijkerman (@dj-wasabi)"
    - "Henryk Plötz (@henryk)"
requirements:
    - "python >= 2.6"
    - zabbix-api
options:
    server_url:
        description:
            - Url of Zabbix server, with protocol (http or https).
        required: true
        aliases: [ "url" ]
    login_user:
        description:
            - Zabbix user name, used to authenticate against the server.
        required: true
    login_password:
        description:
            - Zabbix user password.
        required: true
    http_login_user:
        description:
            - Basic Auth login
        required: false
        default: None
        version_added: "2.1"
    http_login_password:
        description:
            - Basic Auth password
        required: false
        default: None
        version_added: "2.1"
    name:
        description:
            - Name of the proxy in Zabbix.
            - name is the unique identifier used and cannot be updated using this module.
        required: true
    mode:
        description:
            - Proxy mode: active or passive.
        required: false
        choices: ['active', 'passive']
        default: "active"
    state:
        description:
            - State of the proxy entry.
            - On C(present), it will create if proxy does not exist or update the proxy if the associated data is different.
            - On C(absent) will remove a proxy if it exists.
        required: false
        choices: ['present', 'absent']
        default: "present"
    timeout:
        description:
            - The timeout of API request (seconds).
        default: 10
    interfaces:
        description:
            - List of interfaces to be created for the proxy (see example below).
            - Ignored for active mode, required for passive mode.
            - 'Available values are: dns, ip, main, port, type and useip.'
            - Please review the interface documentation for more information on the supported properties
            - 'https://www.zabbix.com/documentation/2.0/manual/appendix/api/proxy/definitions#proxy_interface'
        required: false
        default: []
    tls_connect:
        description:
            - Specifies what encryption to use for outgoing connections.
            - Possible value is "None", "PSK", or "certificate"
            - Ignored for active mode.
        default: "None"
        version_added: "2.4"
    tls_accept:
        description:
            - Specifies what types of connections are allowed for incoming connections.
            - Possible values, "None", "PSK", or "certificate"
            - Values can be combined in a list.
            - Ignored for passive mode.
        default: "['None']"
        version_added: "2.4"
    tls_psk_identity:
        description:
            - PSK value is a hard to guess string of hexadecimal digits.
            - It is a unique name by which this specific PSK is referred to by Zabbix components
            - Do not put sensitive information in PSK identity string, it is transmitted over the network unencrypted.
        required: false
        version_added: "2.4"
    tls_psk:
        description:
            - The preshared key, at least 32 hex digits. Required if either tls_connect or tls_accept has PSK enabled.
        required: false
        version_added: "2.4"
    tls_issuer:
        description:
            - Required certificate issuer.
        required: false
        version_added: "2.4"
    tls_subject:
        description:
            - Required certificate subject.
        required: false
        version_added: "2.4"
    force:
        description:
            - Overwrite the proxy configuration, even if already present
        required: false
        default: "yes"
        choices: [ "yes", "no" ]
        version_added: "2.0"
'''

EXAMPLES = '''
- name: Create a new proxy or update an existing host's info
  local_action:
    module: zabbix_proxy
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    description: ExampleName
    host_groups:
      - Example group1
      - Example group2
    link_templates:
      - Example template1
      - Example template2
    status: enabled
    state: present
    inventory_mode: automatic
    interfaces:
      - type: 1
        main: 1
        useip: 1
        ip: 10.xx.xx.xx
        dns: ""
        port: 10050
      - type: 4
        main: 1
        useip: 1
        ip: 10.xx.xx.xx
        dns: ""
        port: 12345
    proxy: a.zabbix.proxy

- name: Create a new host or update an existing host's tls settings
  local_action:
    module: zabbix_proxy
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    visible_name: ExampleName
    host_groups:
      - Example group1
    tls_psk_identity: test
    tls_connect: PSK
    tls_psk: 123456789abcdef123456789abcdef12

'''

import logging
import copy

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False


class Proxy(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    def add_proxy(self, name, mode, interfaces, tls_connect,
                 tls_accept, tls_psk_identity, tls_psk, tls_issuer, tls_subject):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {'host': name, 'status': mode,
                          'tls_connect': tls_connect, 'tls_accept': tls_accept}
            if tls_psk_identity:
                parameters['tls_psk_identity'] = tls_psk_identity
            if tls_psk:
                parameters['tls_psk'] = tls_psk
            if tls_issuer:
                parameters['tls_issuer'] = tls_issuer
            if tls_subject:
                parameters['tls_subject'] = tls_subject
            if interfaces is not None:
                parameters['interfaces'] = interfaces
            proxy_list = self._zapi.proxy.create(parameters)
            if len(proxy_list) >= 1:
                return proxy_list['proxyids'][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create proxy %s: %s" % (name, e))

    def update_proxy(self, name, mode, proxy_id, interfaces, 
                    tls_connect, tls_accept, tls_psk_identity, tls_psk, tls_issuer, tls_subject):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            parameters = {'proxyid': proxy_id, 'status': mode, 'tls_connect': tls_connect,
                          'tls_accept': tls_accept}
            if tls_psk_identity:
                parameters['tls_psk_identity'] = tls_psk_identity
            if tls_psk:
                parameters['tls_psk'] = tls_psk
            if tls_issuer:
                parameters['tls_issuer'] = tls_issuer
            if tls_subject:
                parameters['tls_subject'] = tls_subject
            if interfaces is not None:
                parameters['interfaces'] = interfaces
            self._zapi.proxy.update(parameters)
        except Exception as e:
            self._module.fail_json(msg="Failed to update proxy %s: %s" % (name, e))

    def delete_proxy(self, proxy_id, name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.proxy.delete([proxy_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete proxy %s: %s" % (name, e))

    # get proxy by proxy name
    def get_proxy_by_name(self, name):
        proxy_list = self._zapi.proxy.get({'output': 'extend', 'selectInterfaces': 'extend', 'filter': {'host': [name]}})
        if len(proxy_list) < 1:
            return None
        else:
            return proxy_list[0]

    # get the mode of proxy by proxy
    def get_proxy_mode_by_proxy(self, proxy):
        return proxy['status']

    @staticmethod
    def _interface_tuples(interfaces):
        return list(sorted( tuple( i.get(k, None) for k in ("dns", "ip", "port", "useip") ) for i in interfaces ))

    # check all the properties before
    def check_all_properties(self, proxy, mode, interfaces, tls_connect_int, tls_accept_int, tls_psk_identity, tls_psk, tls_issuer, tls_subject):
        if int(tls_connect_int) != int(proxy.get('tls_connect',1)):
            return True

        if int(tls_accept_int) != int(proxy.get('tls_accept',1)):
            return True

        if (tls_psk_identity or '') != proxy.get('tls_psk_identity',''):
            return True

        if (tls_psk or '') != proxy.get('tls_psk',''):
            return True

        if (tls_issuer or '') != proxy.get('tls_issuer',''):
            return True

        if (tls_subject or '') != proxy.get('tls_subject',''):
            return True

        # get the existing mode
        exist_mode = self.get_proxy_mode_by_proxy(proxy)
        if int(mode) != int(exist_mode):
            return True

        # check the exist_interfaces whether it equals the interfaces or not
        if self._interface_tuples(proxy.get("interfaces", [])) != self._interface_tuples(interfaces or []):
            return True

        return False

    # Calculate encryption level
    @staticmethod
    def get_encryption_level(parameters):
        settings = {'None': 1, 'PSK': 2, 'certificate': 4}
        value = 0
        for item in parameters:
            value += settings[item]
        if value != 0:
            return value
        else:
            # When nothing or an incorrect params are given, always return 1 (None)
            return 1


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(type='str', required=True, aliases=['url']),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            name=dict(type='str', required=True),
            http_login_user=dict(type='str', required=False, default=None),
            http_login_password=dict(type='str', required=False, default=None, no_log=True),
            mode=dict(default="active", choices=['active', 'passive']),
            state=dict(default="present", choices=['present', 'absent']),
            tls_connect=dict(type='str', default='None'),
            tls_accept=dict(type='list', default=['None']),
            tls_psk_identity=dict(type='str', required=False),
            tls_psk=dict(type='str', required=False),
            tls_issuer=dict(type='str', required=False),
            tls_subject=dict(type='str', required=False),
            timeout=dict(type='int', default=10),
            interfaces=dict(type='list', required=False),
            force=dict(type='bool', default=True),
        ),
        supports_check_mode=True
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing requried zabbix-api module (check docs or install with: pip install zabbix-api)")

    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    http_login_user = module.params['http_login_user']
    http_login_password = module.params['http_login_password']
    name = module.params['name']
    tls_connect = module.params['tls_connect']
    tls_accept = module.params['tls_accept']
    tls_psk_identity = module.params['tls_psk_identity']
    tls_psk = module.params['tls_psk']
    tls_issuer = module.params['tls_issuer']
    tls_subject = module.params['tls_subject']
    mode = module.params['mode']
    state = module.params['state']
    timeout = module.params['timeout']
    interfaces = module.params['interfaces']
    force = module.params['force']

    # convert active mode to 5; passive mode to 6
    mode = 6 if mode == "passive" else 5

    zbx = None
    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)

    proxy = Proxy(module, zbx)

    # Calculate encryption levels
    tls_connect_int = proxy.get_encryption_level(parameters=[tls_connect])
    tls_accept_int = proxy.get_encryption_level(parameters=tls_accept)

    # get proxy object by proxy name
    zabbix_proxy_obj = proxy.get_proxy_by_name(name)

    # Check if proxy already exists
    if zabbix_proxy_obj:
        proxy_id = zabbix_proxy_obj['proxyid']

        if state == "absent":
            # remove proxy
            proxy.delete_proxy(proxy_id, name)
            module.exit_json(changed=True, result="Successfully deleted proxy %s" % name)

        else:
            if not force:
                module.fail_json(changed=False, result="proxy present, Can't update configuration without force")

            if mode == 6:
                if not (interfaces is None and len(zabbix_proxy_obj.get("interfaces",[])) > 0) \
                        and not (interfaces is not None and len(interfaces) > 0):
                    module.fail_json(msg="Specify at least one interface for updating passive proxy '%s'." % name)

            if proxy.check_all_properties(zabbix_proxy_obj, mode, interfaces,
                    tls_connect_int, tls_accept_int, tls_psk_identity, tls_psk, tls_issuer, tls_subject):
                proxy.update_proxy(name, mode, proxy_id, interfaces,
                                 tls_connect_int, tls_accept_int, tls_psk_identity, tls_psk, tls_issuer, tls_subject)
                module.exit_json(changed=True,
                                 result="Successfully updated proxy %s"
                                        % (name,))
            else:
                module.exit_json(changed=False)
    else:
        if state == "absent":
            # the proxy is already deleted.
            module.exit_json(changed=False)

        if mode == 6 and not interfaces:
            module.fail_json(msg="Specify at least one interface for creating passive proxy '%s'." % name)

        # create proxy
        proxy_id = proxy.add_proxy(name, mode, interfaces, tls_connect_int,
                                tls_accept_int, tls_psk_identity, tls_psk, tls_issuer, tls_subject)
        module.exit_json(changed=True, result="Successfully added proxy %s" % (
            name,))


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
