"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

MOCK_URL = "https://192.168.1.1:8006"

MOCK_AUTHENTICATE = {
    "data": {
        "ticket": "PVE:user_1@pam:650DC00D::E8G0zZDEpzUFll3MvSrm5BAG7J4V5AOd4mi7p1u1xHuz5chXwdwkf1wb1IU4XdgXfXq+M2aCDNZDaTPJFBaYT72kXDpPA0v3VdtPMtImaV8xgKEAAJ73ZGOZlQ2bDzF+Z6cMSBZVOaJ5NSE56tf3lh6V/AFPcPMMA9DHG5CMwAytMYGrT9o2qSQA3BYgabPDm2g83Bd9bgiPFdfkgFHoc7GlCGUboXqf0WGgxYQkI0B+2RhahD/SMFHCa/gxKWqfqZQPrJE4N4RyAY5GjHVVmDW13tPEZ4DDW3HcpN/zWJzgWfD43AcLDpwiwrQYQ5b6jHSB1ob0cM9gsQWBvAQqlA==",
        "clustername": "ProxmoxCluster",
        "CSRFPreventionToken": "650DC00D:wEA4q/webRGPVeTYDs1Mo04guW4gfDINsUOL69p3amw",
        "cap": {
            "dc": {
                "SDN.Audit": 1,
                "SDN.Allocate": 1,
                "Sys.Audit": 1
            },
            "sdn": {
                "SDN.Allocate": 1,
                "SDN.Audit": 1,
                "Permissions.Modify": 1
            },
            "nodes": {
                "Sys.Audit": 1,
                "Permissions.Modify": 1,
                "Sys.Console": 1,
                "Sys.PowerMgmt": 1,
                "Sys.Modify": 1,
                "Sys.Syslog": 1
            },
            "access": {
                "Group.Allocate": 1,
                "User.Modify": 1,
                "Permissions.Modify": 1
            },
            "vms": {
                "VM.Config.CPU": 1,
                "VM.Config.Disk": 1,
                "VM.Config.Options": 1,
                "VM.Config.CDROM": 1,
                "VM.Config.Network": 1,
                "VM.Console": 1,
                "VM.Monitor": 1,
                "VM.Snapshot": 1,
                "VM.Clone": 1,
                "VM.Audit": 1,
                "VM.Config.HWType": 1,
                "VM.PowerMgmt": 1,
                "Permissions.Modify": 1,
                "VM.Config.Memory": 1,
                "VM.Allocate": 1,
                "VM.Config.Cloudinit": 1,
                "VM.Migrate": 1,
                "VM.Backup": 1,
                "VM.Snapshot.Rollback": 1
            },
            "storage": {
                "Permissions.Modify": 1,
                "Datastore.AllocateSpace": 1,
                "Datastore.AllocateTemplate": 1,
                "Datastore.Allocate": 1,
                "Datastore.Audit": 1
            }
        },
        "username": "user_1@pam"
    }
}

MOCK_LIST_NODES = {
    "data": [
        {
            "node": "node_1",
            "ssl_fingerprint": "38:71:36:D5:E8:BD:96:FD:FE:76:AC:67:34:5F:A3:91:8C:03:22:81:08:07:10:1E:8B:CD:CF:BA:7E:CC:D4:BC",
            "id": "node/node_1",
            "status": "offline",
            "type": "node"
        },
        {
            "disk": 85595516928,
            "maxmem": 67489615872,
            "type": "node",
            "cpu": 0.0108934456243134,
            "maxdisk": 100861726720,
            "level": "",
            "node": "node_2",
            "maxcpu": 32,
            "ssl_fingerprint": "38:71:36:D5:E8:BD:96:FD:FE:76:AC:67:34:5F:A3:91:8C:03:22:81:08:07:10:1E:8B:CD:CF:BA:7E:CC:D4:BC",
            "status": "online",
            "mem": 21934137344,
            "id": "node/node_2",
            "uptime": 697394
        }
    ]
}

MOCK_LIST_VMS = {
    "data": [
        {
            "mem": 0,
            "netin": 0,
            "disk": 0,
            "netout": 0,
            "cpu": 0,
            "maxdisk": 53687091200,
            "diskwrite": 0,
            "name": "dev-project",
            "uptime": 0,
            "vmid": 124,
            "maxmem": 4294967296,
            "diskread": 0,
            "status": "stopped",
            "cpus": 4
        },
        {
            "disk": 0,
            "pid": 2230,
            "netin": 140216415,
            "mem": 3282294341,
            "cpu": 0,
            "netout": 5108609,
            "vmid": 116,
            "maxdisk": 53687091200,
            "diskwrite": 0,
            "name": "OpenCVE-Engine2",
            "uptime": 756653,
            "cpus": 4,
            "status": "running",
            "maxmem": 4294967296,
            "diskread": 0
        }
    ]
}

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from BaseIntegration import Client, baseintegration_dummy_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {
        'dummy': 'this is a dummy response'
    }
    response = baseintegration_dummy_command(client, args)

    mock_response = util_load_json('test_data/baseintegration-dummy.json')

    assert response.outputs == mock_response
# TODO: ADD HERE unit tests for every command
