"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
import requests
import json

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
        # debug(f'self.context: {self.context}')
        if self.context == '':
            self.authenticate()

        else:
            self.headers = {
                'Content-Type': 'application/json',
                'CSRFPreventionToken': self.context['csrfToken']
            }
            self.cookies = { 'PVEAuthCookie': self.context['authCookie'] }


    def http_request(self, method, url_suffix, params=None, data=None, cookies=None):
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
        debug(f'res.json(): {res.json()}')

        if res.status_code == 401:
            self.authenticate()
        elif res.status_code not in [200, 201, 204]:
            raise ValueError(f'Error [{res.status_code}]: {res.text}')

        try:
            return res.json()
        except Exception:
            raise ValueError(f'Error: [{res.status_code}] {res.text}')

    def authenticate(self):
        body = {
            'username': self.username,
            'password': self.password
        }
        
        # debug(f'body: {body}')
        
        body = remove_empty_elements(body)
        response = self.http_request(method='POST',
                                     url_suffix='access/ticket',
                                     data=body)

        # debug(f'response: {response}')

        self.headers = {
            'Content-Type': 'application/json',
            'CSRFPreventionToken': self.context['csrfToken']
        }
        self.cookies = { 'PVEAuthCookie': self.context['authCookie'] }

        demisto.setIntegrationContext({
            'authCookie': response['data']['ticket'],
            'csrfToken': response['data']['CSRFPreventionToken']
        })

        return response['data']

    def list_nodes(self, retry=False):
        response = self.http_request(method='GET',
                                     url_suffix='nodes',
                                     cookies=self.cookies)
        
        return response['data']

    def list_vms(self, node=None):
        if node is None:
            raise ValueError(f'Error: No node name provided')

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

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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


# TODO: REMOVE the following dummy command function
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
    
    return CommandResults(
        outputs_prefix='Proxmox',
        outputs_key_field='nodes',
        outputs=result
    )


def proxmox_list_vms(client: Client, args: dict) -> CommandResults:
    node = args.get('node', None)
    result = client.list_vms(node)
    
    return CommandResults(
        outputs_prefix='Proxmox',
        outputs_key_field='vms',
        outputs=result,
    )


def proxmox_start_vm(client: Client, args: dict) -> CommandResults:
    node = args.get('node', None)
    vm_id = args.get('vm-id', None)
    result = client.start_vm(node, vm_id)
    
    return CommandResults(
        outputs_prefix='Proxmox',
        outputs_key_field='vms',
        outputs=result,
    )


def proxmox_shutdown_vm(client: Client, args: dict) -> CommandResults:
    node = args.get('node', None)
    vm_id = args.get('vm-id', None)
    result = client.shutdown_vm(node, vm_id)
    
    return CommandResults(
        outputs_prefix='Proxmox',
        outputs_key_field='vms',
        outputs=result,
    )


def main():
    '''main function, parses params and runs command functions'''

    # TODO: make sure you properly handle authentication
    # api_key = params.get('apikey')

    params = demisto.params()
    # get the service API url
    base_url = urljoin(params.get('url'), "api2/json")

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    # verify_certificate = not argToBoolean(params('insecure', False))
    verify = False

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    # proxy = argToBoolean(params.get('proxy', False))
    proxy = False

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    username = params.get('username')
    password = params.get('password')

    try:
        headers = {}

        client = Client(
            base_url=base_url, verify=verify, username=username,
            password=password, headers=headers, proxy=proxy
        )
        args = demisto.args()
        
        # Commands
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)

        elif command == "proxmox-capabilites":
            result = proxmox_capabilities(client)
        elif command == "proxmox-list-nodes":
            result = proxmox_list_nodes(client)
        elif command == "proxmox-list-vms":
            result = proxmox_list_vms(client, args)
        elif command == "proxmox-vm-start":
            result = proxmox_start_vm(client, args)
        elif command == "proxmox-vm-shutdown":
            result = proxmox_shutdown_vm(client, args)
            
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
