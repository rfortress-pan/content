'''
# TODO
[] Create tests
[] Fix context outputs
[] Fix MD outputs
[] Fix user/pass params
[] Create pack README
[] Create integration README
[] Add icon
'''

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
import requests
import json
import math
import datetime

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

import requests
def debug(msg, url='http://192.168.4.8:1880', endpoint='debug'):
    url = f'{url}/{endpoint}'
    if type(msg) in [dict, list]:
        return requests.post(url, json=msg)
    return requests.post(url, data=f'{msg}')

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):

    def __init__(self, base_url: str, username: str, password: str,
                 verify: bool, proxy: bool, headers: dict):
        self.base_url = base_url
        self.verify = verify
        self.username = username
        self.password = password
        self.context = demisto.getIntegrationContext()

        if self.context == '':
            self.authenticate()

        else:
            self.headers = {
                'Content-Type': 'application/json',
                'CSRFPreventionToken': self.context['csrfToken']
            }
            self.cookies = { 'PVEAuthCookie': self.context['authCookie'] }

    def http_request(self, method, url_suffix, params=None, data=None, cookies=None, retry=False):
        full_url = urljoin(self.base_url, url_suffix)

        debug(f'full_url: {full_url}')
        debug(f'headers: {self.headers}')
        debug(f'cookies: {self.cookies}')

        if method == 'POST' and data is None:
            data = {}

        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            params=params,
            headers=self.headers,
            json=data,
            cookies=cookies
        )
        debug(f'status_code: {res.status_code}')
        debug(f'res.text: {res.text}')
        # debug(f'res.json(): {res.json()}')

        # 401 permission denied - invalid PVE ticket
        if res.status_code == 401:
            debug('got 401')
            if retry:
                debug('retry was True and got a 401, failing')
                raise ValueError(f'[{res.status_code}]: {res.text}')

            debug('getting fresh authentication')
            self.authenticate(retry=True)
            debug('trying request again')
            self.http_request(method, url_suffix, params, data, cookies, retry=True)

        elif res.status_code not in [200, 201, 204]:
            raise ValueError(f'[{res.status_code}] {res.text}')

        try:
            return res.json()
        except Exception:
            raise ValueError(f'[{res.status_code}] {res.text}')

    def authenticate(self, retry=False):
        debug(f'calling authenticate(retry={retry})')
        body = {
            'username': self.username,
            'password': self.password
        }
        
        response = self.http_request(method='POST',
                                     url_suffix='access/ticket',
                                     data=body, retry=retry)

        self.context = {
            'authCookie': response['data']['ticket'],
            'csrfToken': response['data']['CSRFPreventionToken']
        }
        demisto.setIntegrationContext(self.context)

        self.headers = {
            'Content-Type': 'application/json',
            'CSRFPreventionToken': self.context['csrfToken']
        }
        self.cookies = { 'PVEAuthCookie': self.context['authCookie'] }

        return response['data']

    def list_nodes(self):
        response = self.http_request(method='GET',
                                     url_suffix='nodes',
                                     cookies=self.cookies)
        
        return response['data']

    def list_vms(self, node=None):
        if node is None:
            raise ValueError('No node name provided.\nUse !proxmox-list-nodes for list of available nodes.')

        response = self.http_request(method='GET',
                                     url_suffix=f'nodes/{node}/qemu/',
                                     cookies=self.cookies)

        debug(f'response: {response}')

        return response['data']

    def start_vm(self, node=None, vm_id=None):
        if node is None:
            raise ValueError(f'Error: No node name provided')
        if vm_id is None:
            raise ValueError(f'Error: No vm_id provided')

        response = self.http_request(method='POST',
                                     url_suffix=f'nodes/{node}/qemu/{vm_id}/status/start',
                                     cookies=self.cookies)

        return response['data']

    def shutdown_vm(self, node=None, vm_id=None):
        if node is None:
            raise ValueError(f'Error: No node name provided')
        if vm_id is None:
            raise ValueError(f'Error: No vm_id provided')

        response = self.http_request(method='POST',
                                     url_suffix=f'nodes/{node}/qemu/{vm_id}/status/shutdown',
                                     cookies=self.cookies)

        return response['data']


""" HELPER FUNCTIONS """

def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])


def convert_time(seconds):
    return str(datetime.timedelta(seconds=seconds))

""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.authenticate()
    debug(result)
    
    return "ok"


def proxmox_capabilities(client: Client) -> CommandResults:
    # Call the Client function and get the raw response
    result = client.authenticate()

    return CommandResults(
        outputs_prefix='Proxmox',
        outputs_key_field='capabilities',
        outputs=result['cap'],
    )


def proxmox_list_nodes(client: Client) -> CommandResults:
    result = client.list_nodes()
    nodes = {}
    node_list = []
    
    for item in result:
        node = {
            'node': item['node'],
            'status': item['status']
        }

        if item['status'] == 'online':
            node['cpu'] = f'{round(item["cpu"]*10000)/100}% of {item["maxcpu"]} CPU(s)'
            node['mem'] = f'{(round((item["mem"] / item["maxmem"]) *10000)/100)}% ({convert_size(item["mem"])} of {convert_size(item["maxmem"])})'
            node['disk'] = f'{(round((item["disk"] / item["maxdisk"]) *10000)/100)}% ({convert_size(item["disk"])} of {convert_size(item["maxdisk"])})'
            node['uptime'] = convert_time(item['uptime'])

        else:
            node['cpu'] = 'N/A'
            node['mem'] = 'N/A'
            node['disk'] = 'N/A'
            node['uptime'] = 'N/A'

        node_list.append(node)
        nodes[item['node']] = item
    
    markdown = tableToMarkdown('Proxmox Nodes', node_list, headers=['node', 'status', 'cpu', 'mem', 'disk', 'uptime'])
    
    return CommandResults(
        outputs_prefix='Proxmox.Nodes',
        outputs_key_field='nodes',
        readable_output=markdown,
        outputs=nodes
    )


def proxmox_list_vms(client: Client, args: dict) -> CommandResults:
    node = args.get('node', None)
    result = client.list_vms(node)
    vms = {}
    vm_list = []
    
    for item in result:
        vm = {
            'vmid': item['vmid'],
            'status': item['status'],
            'name': item['name'],
            'disk': f'{convert_size(item["maxdisk"])}'
        }
        if item['status'] == 'running':
            vm['cpu'] = f'{round(item["cpu"]*10000)/100}% of {item["cpus"]} CPU(s)'
            vm['mem'] = f'{(round((item["mem"] / item["maxmem"]) *10000)/100)}% ({convert_size(item["mem"])} of {convert_size(item["maxmem"])})'
            vm['uptime'] = convert_time(item['uptime'])
        else:
            vm['cpu'] = f'{item["cpus"]}'
            vm['mem'] = f'{convert_size(item["maxmem"])}'
            vm['uptime'] = 'N/A'
        vm_list.append(vm)
        vms[item['vmid']] = item
        
    vm_list = sorted(vm_list, key=lambda x: x['vmid'])
    markdown = tableToMarkdown(f'Proxmox {node} VMs', vm_list, headers=['vmid', 'name', 'status', 'cpu', 'mem', 'disk', 'uptime'])
        
    return CommandResults(
        outputs_prefix=f'Proxmox.{node}.VMs',
        outputs_key_field='vms',
        readable_output=markdown,
        outputs=vms
    )        


def proxmox_start_vm(client: Client, args: dict) -> CommandResults:
    node = args.get('node', None)
    vm_id = args.get('vm-id', None)
    result = client.start_vm(node, vm_id)
    
    markdown = f'### Proxmox\nStarting VM with id `{vm_id}` on node `{node}`...'
    
    return CommandResults(
        outputs_prefix=f'Proxmox.{node}.{vm_id}.Start',
        readable_output=markdown,
        outputs=result
    )


def proxmox_shutdown_vm(client: Client, args: dict) -> CommandResults:
    node = args.get('node', None)
    vm_id = args.get('vm-id', None)
    result = client.shutdown_vm(node, vm_id)
    
    markdown = f'### Proxmox\nShutting down VM with id `{vm_id}` on node `{node}`...'

    return CommandResults(
        outputs_prefix=f'Proxmox.{node}.{vm_id}.Shutdown',
        readable_output=markdown,
        outputs=result
    )


def main():
    '''main function, parses params and runs command functions'''

    params = demisto.params()
    base_url = urljoin(params.get('url'), "api2/json")

    # verify_certificate = not argToBoolean(params('insecure', False))
    # proxy = argToBoolean(params.get('proxy', False))
    verify_certificate = False
    proxy = False

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    username = params.get('username')
    password = params.get('password')

    try:
        headers = {}

        client = Client(
            base_url=base_url, verify=verify_certificate, username=username,
            password=password, headers=headers, proxy=proxy
        )
        args = demisto.args()
        
        # Commands
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)

        elif command == 'proxmox-capabilites':
            result = proxmox_capabilities(client)
        elif command == 'proxmox-list-nodes':
            result = proxmox_list_nodes(client)
        elif command == 'proxmox-list-vms':
            result = proxmox_list_vms(client, args)
        elif command == 'proxmox-vm-start':
            result = proxmox_start_vm(client, args)
        elif command == 'proxmox-vm-shutdown':
            result = proxmox_shutdown_vm(client, args)
            
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
