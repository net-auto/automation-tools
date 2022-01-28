import sys
from collections import defaultdict
from dataclasses import dataclass
from ipaddress import IPv4Address, AddressValueError, IPv4Interface, IPv4Network
from time import sleep

import keyring
import progressbar
import requests.packages.urllib3
from pyhpeimc.auth import *
from pyhpeimc.objects import *
from pyhpeimc.plat.groups import *
from requests.auth import HTTPDigestAuth


@dataclass
class SwitchInventory:
    imc_id: str
    hostname: str
    subnet_mask: str
    ip_address: IPv4Address
    ipv4_prefix: IPv4Network
    sys_description: str
    type_name: str
    imc_parent_id: str
    sys_location: str


# disable ssl cert check:
requests.packages.urllib3.disable_warnings()

# global variables:
# url = self.h_url + self.imc_server + ":" + self.imc_port
h_url = "https"
imc_server = "<IMC_FQDN>"
imc_port = "8443"


# general functions:
def create_switch_inventory(imc_username, imc_password) -> dict:
    switch_inventory = dict()
    imc_inventory = get_imc_devices(imc_username, imc_password)
    for ipv4, switch_data in imc_inventory.items():
        temp_inventory = SwitchInventory(imc_id=switch_data["imc_id"],
                                         hostname=switch_data["hostname"],
                                         subnet_mask=switch_data["subnet_mask"],
                                         ip_address=ipv4,
                                         ipv4_prefix=IPv4Interface(
                                             f'{ipv4.compressed}/{switch_data["subnet_mask"]}').network,
                                         sys_description=switch_data["sys_description"],
                                         type_name=switch_data["type_name"],
                                         imc_parent_id=switch_data["imc_parent_id"],
                                         sys_location=switch_data["sys_location"]
                                         )
        switch_inventory.update({ipv4: temp_inventory})
    return switch_inventory


def get_access_switches(imc_device_inventory: dict, specific_prefix: IPv4Network) -> dict:
    """
    other models then 5130, need to be implemented if needed

    Args:
        imc_device_inventory:
        specific_prefix:

    Returns:
    only the access switches (5130)
    """
    result = dict()
    for ipv4, switch_data in imc_device_inventory.items():
        if "HPE 5130".lower() in str(switch_data.type_name).lower():
            if ipv4 in specific_prefix:
                result.update({ipv4: switch_data})
    return result


def real_time_locate_by_ip(imc_user, imc_pass, host_ip_or_mac, host_or_ip_type="ip"):
    """
    example MAC: 6c:ab:05:b2:46:88
    """
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    auth = HTTPDigestAuth(imc_user, imc_pass)
    if host_or_ip_type == "ip":
        url = \
            f"https://<IMC_FQDN>:8443/imcrs/res/access/realtimeLocate?type=2&value={host_ip_or_mac}&total=false"
    elif host_or_ip_type == "mac":
        url = \
            f"https://<IMC_FQDN>:8443/imcrs/res/access/realtimeLocate?type=1&value={host_ip_or_mac}&total=false"
    response = requests.get(url, headers=headers, auth=auth, verify=False)
    if response.status_code == 200:
        # convert the response to a dict:
        response_dict = eval(response.text)
        return response_dict
    else:
        print("REQUEST FAILED")
        print("ERROR CODE:", response.status_code)
        print("ERROR REASON:", response.reason)


def create_interface_dict(imc_dev_obj):
    """
    create a interface dict from the IMCdev accessinterfaces and interface_list method
    """
    switch_int_dict = defaultdict(dict)
    # accessinterfaces = imc_dev_obj.accessinterfaces
    interface_list = imc_dev_obj.interfacelist
    # trunkinterfaces = imc_dev_obj.trunkinterfaces
    for interface in interface_list:
        if interface.get("ifAlias").startswith("Gi") or interface.get("ifAlias").startswith("Te"):
            temp_dict_access = {interface.get("if_index"): [interface.get("ifDescription"), interface.get("ifAlias"),
                                                            interface.get("operationStatusDesc")]}
            switch_int_dict[imc_dev_obj.ip].update(temp_dict_access)
    return switch_int_dict


def get_ssh_template_list(imc_username, imc_password):
    auth = HTTPDigestAuth(imc_username, imc_password)
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    url = "https://<IMC_FQDN>:8443/imcrs/plat/res/ssh?size=100"
    response = requests.get(url, headers=headers, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        # convert the response to a dict:
        response_dict = eval(response.text)
        return response_dict
    else:
        print("REQUEST FAILED")
        print("ERROR CODE:", response.status_code)
        print("ERROR REASON:", response.reason)
    return response


def delete_ssh_template_by_id(template_id, imc_username, imc_password):
    auth = HTTPDigestAuth(imc_username, imc_password)
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    url = f"https://<IMC_FQDN>:8443/imcrs/plat/res/ssh/{template_id}/delete"
    response = requests.delete(url, headers=headers, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 204:
        # convert the response to a dict:
        # responseDict = eval(response.text)
        return response
    else:
        print("REQUEST FAILED")
        print("ERROR CODE:", response.status_code)
        print("ERROR REASON:", response.reason)


def sent_cli_cmd(ip_address, imc_cmd_list, auth_creds, auth_url):
    """
    connects to the switch and performs the command: "display user"
    to check if IMC is able to connect to the switch via the current
    SSH profile set
    """
    # print(f"INFO: CONNECTING TO IP: {ip_address}")
    try:
        dev_cmd_response = run_dev_cmd(imc_cmd_list, auth_creds, auth_url, devip=ip_address)
        # print("DEBUG: dev_cmd_response:", dev_cmd_response)
        if dev_cmd_response['success'] == "true":
            # print("CMD WAS SUCCESSFUL")
            result = "OK"
            return result
        else:
            # print("CMD WAS NOT SUCCESSFUL")
            return dev_cmd_response['errorMsg']
    except Exception as e:
        print("ERROR: ", e)


def create_hostname_from_ip(mgmt_ip, country_code):
    """
    example country code: CH, UK
    creates the switch hostname based on the mgmt IP and the country code
    """
    temp_ip_split = mgmt_ip.split(".")
    hostname = f"SWI{country_code}{temp_ip_split[1].zfill(3)}{temp_ip_split[2].zfill(3)}{temp_ip_split[3].zfill(3)}"
    hostname = hostname.upper()
    return hostname


def get_imc_dev_run_cfg(dev_id, imc_username, imc_password):
    """
    Example REQUEST:
    https://<IMC_FQDN>:8443/imcrs/icc/deviceCfg/1200/latestRun
    {
    "devFileNamePath": "<hostname>_running_20210502120945.cfg",
    "dev_id": "1200",
    "fileType": "0",
    "backupAt": "2021-05-02 12:09:52:000",
    "content": "#\r\n version 7.1.070, Release 3506P06\r\n#\r\n sysname <hostname> ...omitted..."
    }
    """
    auth = HTTPDigestAuth(imc_username, imc_password)
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}

    url = f'https://<IMC_FQDN>:8443/imcrs/icc/deviceCfg/{dev_id}/latestRun'
    response = requests.get(url, headers=headers, auth=auth, verify=False)
    if response.status_code == 200:
        content = response.json()['content']
        return content
    else:
        response.raise_for_status()


def get_imc_devices(imc_username, imc_password):
    """
    get the current switches/devices from IMC
    only managed devices of the category = "switch"
    and returns a dict object with IP, Hostname and device ID:
    IPv4Address('IP_ADDRESS'): ['HOSTNAME', 'DEVICE_ID']
    """
    headers_json = {'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Accept-encoding': 'application/json'}
    url = "https://<IMC_FQDN>:8443/imcrs/plat/res/device?size=1000"
    device_dict = dict()
    response = requests.get(url, headers=headers_json, auth=HTTPDigestAuth(imc_username, imc_password), verify=False)

    if response.status_code == 200:
        j_response = response.json()
        # dict_response = json.loads(json_dumps(j_response))
        # add devices from IMC only if the switch is not in "unmanaged" state (-1)
        for i in j_response['device']:
            if i["status"] != "-1" and 'switch' in i["devCategoryImgSrc"]:
                device_dict[IPv4Address(i["ip"])] = \
                    dict(hostname=i["label"], imc_id=i["id"], subnet_mask=i["mask"],
                         sys_description=i["sysDescription"], type_name=i["typeName"], imc_parent_id=i["parentId"],
                         sys_location=i['location'])
        return device_dict

    else:
        print("IMC API GET WAS NOT SUCCESSFUL!")
        print("Is the imc_username/imc_password correct?")
        sys.exit()  # exit the execution, because this is needed


def get_imc_switch_ips(imc_username, imc_password):
    """
    gets all currently managed switches from IMC

    Args:
        imc_username: str
        imc_password: str

    Returns:
        a list containing the switch IP addresses

    """
    headers_json = {'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Accept-encoding': 'application/json'}
    url = "https://<IMC_FQDN>:8443/imcrs/plat/res/device?size=1000"
    ip_list = list()
    response = requests.get(url, headers=headers_json, auth=HTTPDigestAuth(imc_username, imc_password), verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        j_response = response.json()
        for i in j_response['device']:
            if i["status"] != "-1" and 'switch' in i["devCategoryImgSrc"]:
                temp_ip = IPv4Address(i['ip'])
                ip_list.append(temp_ip)
        return ip_list


def create_mpls_interface_desc(router_name, line_id, role):
    """
    pattern for interfaces with MPLS router connected:
    - <MPLS_PROVIDER><ROLE><MPLS><ROUTER_NAME><LINE_ID>
    """
    if role.lower() == "main":
        result = f'<MPLS_PROVIDER><MAIN><MPLS><{router_name}><{line_id}>'
        return result
    elif role.lower() == "backup":
        result = f'<MPLS_PROVIDER><BACKUP><MPLS><{router_name}><{line_id}>'
        return result


def get_deleted_device_from_operator_log(imc_username, imc_password):
    deleted_device = set()
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    payload = {}
    module_name = "Device Resource"
    operation_result = "1"  # 1 = success, 0 = failure, 2 = part success)
    operation_desc = "Delete device"  # search string for deleted devices
    url = \
        f"https://<IMC_FQDN>:8443/imcrs/operationLog?start=0&size=1000&moduleName={module_name}" \
        f"&operationResult={operation_result}&operationDesc={operation_desc}"
    response = requests.get(url, headers=headers, data=payload, auth=HTTPDigestAuth(imc_username, imc_password),
                            verify=False)
    operator_log = response.json()["operationLog"]
    if isinstance(operator_log, dict):
        ipv4_string = extract_ipv4_from_operator_log(operator_log['description'])
        deleted_device.add(ipv4_string)
    if isinstance(operator_log, list):
        for entry in operator_log:
            ipv4_string = extract_ipv4_from_operator_log(entry['description'])
            deleted_device.add(ipv4_string)
    return deleted_device


def extract_ipv4_from_operator_log(description):
    try:
        start_idx = description.rindex('(') + 1
        end_idx = description.rindex(')')
        ipv4_string = description[start_idx:end_idx]
        # test if ipv4_string is an IPv4 address:
        assert IPv4Address(ipv4_string)
        return ipv4_string
    except AddressValueError:
        print(f"invalid IPv4 address: {ipv4_string}")
        return False
    except ValueError:
        print(f"invalid input string: {description}")
        print("IP address must be in parenthesis ()")
        return False


def create_ip_list_from_operator_log(json_response_operator_log):
    """
    creates a list with deleted device at IMC
    Only added to the list, if the operation was successful
    """
    deleted_ips = list()
    for i in json_response_operator_log:
        print(i)
        if i["resultStr"] == "Success":
            start_index = i["description"].rindex("(") + 1
            end_index = i["description"].rindex(")")
            deleted_ips.append(i["description"][start_index:end_index])
    return deleted_ips


def check_device_at_imc(ipv4_dev_ip, imc_devices: dict):
    """
    check if device exsists at IMC and returns:
    True = if exsists
    False = if not exsists
    """
    if ipv4_dev_ip in imc_devices:
        device_exist = True
    else:
        device_exist = False
    return device_exist


def add_device(device_ip, auth_token):
    """
    adds a new device at IMC via API POST
    """
    headers = {'Content-type': 'application/json'}
    payload = {"supportPing": "true",  # Support for the ping operation
               "registerTrap": "true",  # Send traps to the NMS
               "forceAdd": "true",  # add device regardless of the IP reachability
               "nameOrIp": device_ip,  # Host or IP address
               # "mask": devMask, # will be discovered by IMC itself
               # "label": hostname, # will be discovered by IMC itself
               "sshTmplId": "845",  # https://<IMC_FQDN>:8443/imcrs/plat/res/ssh/845
               "snmpTmplId": "1",  # https://<IMC_FQDN>:8443/imcrs/plat/res/snmp/1
               "loginType": "2"  # = SSH
               }
    # print("DEBUG payload:", payload)
    json_data = json.dumps(payload)
    url = "https://<IMC_FQDN>:8443/imcrs/plat/res/device"
    # print(json_data)
    # url = http_url + imc_url + "8443" + api_dev_url
    # print(url)
    response = requests.post(
        url,
        headers=headers,
        auth=auth_token,
        data=json_data,
        verify=False
    )
    response.raise_for_status()
    if response.status_code == 201:
        print(f'SWITCH WITH IP: {device_ip} SUCCESSFULLY CREATED')
    else:
        print("REQUEST FAILED")
        print("ERROR CODE:", response.status_code)
        print("ERROR REASON:", response.reason)
    return response


def create_ntp_undo_config(imc_dev_run_cfg, ntp_default_ip):
    """
    creates a syntax list with all non compliant ntp imc_server
    """
    device_ntp_undo_config = list()
    for idx, ntp in enumerate(imc_dev_run_cfg.splitlines()):
        if "ntp-service unicast-imc_server" in ntp and ntp_default_ip not in ntp:
            temp_string = f"undo {ntp.replace('priority', '').strip()}"
            device_ntp_undo_config.append(temp_string)
    return device_ntp_undo_config


def create_new_ntp_config(device_ntp_undo_config):
    """
    returns the needed syntax to remove the non-compliant config
    """
    device_ntp_undo_config.insert(0, 'system-view')
    device_ntp_undo_config.append('ntp-service enable')
    device_ntp_undo_config.append('ntp-service unicast-imc_server 172.25.48.5 priority')
    return device_ntp_undo_config


def createLoghostUndoConfig(IMCDevRunCfg, LOGHOST_DEFAULT_ADRESS):
    """
    creates a syntax list with all non compliant ntp imc_server
    """
    deviceLoghostUndoConfig = list()
    for idx, loghost in enumerate(IMCDevRunCfg.splitlines()):
        if "info-center loghost " in loghost and LOGHOST_DEFAULT_ADRESS not in loghost:
            tempString = f"undo {loghost.strip()}"
            deviceLoghostUndoConfig.append(tempString)
    return deviceLoghostUndoConfig


def createNewLoghostConfig(deviceLoghostUndoConfig):
    """
    returns the needed syntax to remove the non-compliant config
    """
    deviceLoghostUndoConfig.insert(0, 'system-view')
    deviceLoghostUndoConfig.append('info-center enable')
    deviceLoghostUndoConfig.append('info-center loghost 172.25.32.78')
    return deviceLoghostUndoConfig


def getRealTimeAlerts(imcUsername, imcPassword):
    """
    gets the realtime alerts from IMC and return a list
    with the values as dict
    """
    url = f"https://<IMC_FQDN>:8443/imcrs/fault/faultRealTime?operatorName={imcUsername}"
    payload = {}
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    response = requests.get(url, headers=headers, auth=auth, data=payload, verify=False)
    response.raise_for_status()
    realTimeAlerts = eval(response.text)["faultRealTime"]["faultRealTimeList"]
    return realTimeAlerts


def getAlertsUnackDown(imcUsername, imcPassword):
    """
    ackStatus=1 = Acknowledged
    alarmLevel=1 = Critical
    recStatus=0 = Unrecovered
    size=150 = number of entries to get
    alarmCategory=2 = Device Availability Alarm
    """
    ackStatus = "1"
    alarmLevel = "1"
    recStatus = "0"
    alarmCategory = "2"
    url = \
        f"https://<IMC_FQDN>:8443/imcrs/fault/alarm?operatorName={imcUsername}&size=150&alarmLevel=" \
        f"{alarmLevel}&ackStatus={ackStatus}&recStatus={recStatus}&alarmCategory={alarmCategory}"
    payload = {}
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    response = requests.get(url, headers=headers, auth=auth, data=payload, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        alertsUackDown = eval(response.text)
        return alertsUackDown
    else:
        print("Error getting Alarms at IMC")


def getImcDeviceAssets(devIp, imcUsername, imcPassword):
    """
    https://<IMC_FQDN>:8443/imcrs/netasset/asset?assetPhyClass=9&assetDevice.ip=172.17.4.1&start=0&size=10&total=false
    """
    # pyhClass 3 =  for standalone device -> lesser payload in response
    phyClass = "3"
    # assetPhyClass={phyClass}&

    url = f"https://<IMC_FQDN>:8443/imcrs/netasset/asset?assetPhyClass={phyClass}&assetDevice.ip={devIp}"
    payload = {}
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    while True:
        try:
            response = requests.get(url, headers=headers, auth=auth, data=payload, verify=False)
            response.raise_for_status()
            if response.status_code == 200:
                deviceAssetResponse = json.loads(response.text)['netAsset']
                return deviceAssetResponse
            else:
                # print("Error getting asset details")
                deviceAssetResponse = "NO_DATA"
                return deviceAssetResponse
        except:
            sleep(10)  # wait 10 seconds before retry
            print("Retrying getting Asset. Waiting 10 sec...")
            continue
        break


def getSoftwareVersion(imcDeviceAsset):
    """
    creates a dict with the hostname and the software version
    matching criteria will be:
    - if softVersion is not empty
    """
    # print(type(imcDeviceAsset))
    if isinstance(imcDeviceAsset, dict):
        softwareVersion = imcDeviceAsset.get("softVersion")
        return softwareVersion
    elif isinstance(imcDeviceAsset, list):
        for i in imcDeviceAsset:
            if i.get("softVersion"):
                softwareVersion = i.get("softVersion")
                return softwareVersion
    """
    elif type(imcDeviceAsset) == str():
    """


def createSoftwareInventory(imcUserName, imcPassword):
    deviceSwInventory = dict()
    http_url = "https://"
    imc_url = "<IMC_FQDN>"
    imc_port = "8443"
    auth = IMCAuth(http_url, imc_url, imc_port, imcUserName, imcPassword)
    imcDevices = get_imc_devices(imcUserName, imcPassword)

    # create a list of devices as IMCdev object:
    with progressbar.ProgressBar(max_value=len(imcDevices)) as bar:
        for idx, hostnameDevId in enumerate(imcDevices.items(), start=1):
            # imcDevObjects.append(IMCdev(IPv4Address(deviceIp)), auth.credentials, auth.url)
            # print("PROCESSING:", deviceIp)
            try:
                # tempDevObject = IMCDev(IPv4Address(hostnameDevId[0]), auth.credentials, auth.url)
                tempDeviceAsset = getImcDeviceAssets(IPv4Address(hostnameDevId[0]), imcUserName, imcPassword)
                deviceSwInventory[hostnameDevId[1][0]] = getSoftwareVersion(tempDeviceAsset)
                bar.update(idx)
            except:
                deviceSwInventory[hostnameDevId[1][0]] = "NOT_AVAIL"
                bar.update(idx)
    return deviceSwInventory


def checkStpConfig(baseUrl, deviceId, imcUsername, imcPassword):
    """
    connects to the switch and performs the command: "dis current-configuration | in "stp global enable""
    returns true if STP is globally enabled and false if not

    """
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    url = f"https://{baseUrl}:8443/imcrs/icc/confFile/executeCmd"
    payload = json.dumps({
        "device_id": str(deviceId),
        "cmdlist": {
            "cmd": ["dis cu | in \"stp global enable\""]
        }
    })
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.post(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        # convert byte string to dict:
        response = eval(response.content)
    # check if response was successful and the corresponding syntax is found:
    if response["success"] == "true" and "stp global enable" in response["content"]:
        stpIsActive = True
    else:
        stpIsActive = False
    return stpIsActive


def set_stp_config_rstp(baseUrl, deviceId, imcUsername, imcPassword):
    """
    creates the default RSTP config and configure the corresponding switch based on the IMC device ID
    """
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    url = f"https://{baseUrl}:8443/imcrs/icc/confFile/executeCmd"
    payload = json.dumps({
        "device_id": str(deviceId),
        "cmdlist": {
            "cmd": ["system-view",
                    "stp mode rstp",
                    "stp global enable"
                    ]
        }
    })
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.post(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        return response


def set_stp_rstp_dot1t_extension(baseUrl, deviceId, imcUsername, imcPassword):
    """
    creates the default RSTP dot1 extension config and configure the corresponding switch based on the IMC device ID
    """
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    url = f"https://{baseUrl}:8443/imcrs/icc/confFile/executeCmd"
    payload = json.dumps({
        "device_id": str(deviceId),
        "cmdlist": {
            "cmd": ["system-view",
                    "stp pathcost-standard dot1t",
                    "Y",
                    " "
                    ]
        }
    })
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.post(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        return response


def set_stp_rstp_root_bridge(baseUrl, deviceId, imcUsername, imcPassword):
    """
    creates the default RSTP root bridge config with prio: 4096 and
    configure the corresponding switch based on the IMC device ID
    """
    auth = HTTPDigestAuth(imcUsername, imcPassword)
    url = f"https://{baseUrl}:8443/imcrs/icc/confFile/executeCmd"
    payload = json.dumps({
        "device_id": str(deviceId),
        "cmdlist": {
            "cmd": ["system-view",
                    "stp instance 0 priority 4096"
                    ]
        }
    })
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.post(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        return response


def verify_stp_config(base_url, device_id, imc_username, imc_password, enable_rstp, enable_dot1t, root_bridge):
    """
    verify the current STP configuration and return the result as dict()
    """
    auth = HTTPDigestAuth(imc_username, imc_password)
    check_result = dict()
    url = f"https://{base_url}:8443/imcrs/icc/confFile/executeCmd"
    payload = json.dumps({
        "device_id": str(device_id),
        "cmdlist": {
            "cmd": ["display current-configuration configuration | in stp"]
        }
    })
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.post(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        # convert the response to a dict:
        response_dict = eval(response.text)

    if enable_rstp == "x":
        if "stp mode rstp" in response_dict["content"] and "stp global enable" in response_dict["content"]:
            check_result.update({"enable_rstp": "enabled"})
        else:
            check_result.update({"enable_rstp": "not found at the current config"})
    else:
        check_result.update({"enable_rstp": "not selected to be configured"})

    if enable_dot1t == "x":
        if "stp pathcost-standard dot1t" in response_dict["content"]:
            check_result.update({"enable_dot1t": "enabled"})
        else:
            check_result.update({"enable_dot1t": "not found at the current config"})
    else:
        check_result.update({"enable_dot1t": "not selected to be configured"})

    if root_bridge == "x":
        if "stp instance 0 priority 4096" in response_dict["content"]:
            check_result.update({"root_bridge": "enabled"})
        else:
            check_result.update({"root_bridge": "not found at the current config"})
    else:
        check_result.update({"root_bridge": "not selected to be configured"})
    return check_result


def get_lldp_neighbor(os_version, base_url, device_id, imc_username, imc_password):
    """
    build neighbor dict from IMC with the current_ip_address
    return a dict with the current_ip_address : neighbor_ip_address
    os_version: cw5 or cw7
    """
    auth = HTTPDigestAuth(imc_username, imc_password)
    lldp_neighbors = dict()
    display_lldp_neighbor = list()
    url = f"https://{base_url}:8443/imcrs/icc/confFile/executeCmd"
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    if os_version == "cw5":
        # comware 5 (needed for the neighbor IP address):
        display_lldp_neighbor.append('display lldp neighbor-information')

    if os_version == "cw7":
        # comware 7 (needed for the neighbor IP address):
        display_lldp_neighbor.append('display lldp neighbor-information list')

    payload = json.dumps({
        "device_id": str(device_id),
        "cmdlist": {
            "cmd": display_lldp_neighbor
        }
    })
    response = requests.post(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        # convert the response to a dict:
        lldp_neighbors = eval(response.text)
    return lldp_neighbors["content"]


def get_single_device_info(ip, imc_username, imc_password, imc_base_url="<IMC_FQDN>"):
    """
    Example:
    https://<IMC_FQDN>:8443/imcrs/plat/res/device/allMsg/172.17.4.239
    {
      "id": "833",
      "label": "HOSTNAME",
      "ip": "IP_ADDRESS",
      "mask": "255.255.255.0",
      "status": "1",
      "statusDesc": "Normal",
      "sysName": "HOSTNAME",
      "contact": "EMAIL_ADDRESS",
      "location": "<location>",
      "sysOid": "1.3.6.1.4.1.25506.11.1.189",
      "runTime": "97 day(s) 17 hour(s) 16 minute(s) 11 second(s) 0 millisecond(s)",
      "lastPoll": "2021-11-03 07:14:20",
      "loginType": "2",
      .
    <omitted>
    }
    Args:
        imc_base_url: default = <IMC_FQDN> -> override if needed
        imc_password:
        imc_username:
        ip: IPv4 in str() format

    Returns:

    """
    auth = HTTPDigestAuth(imc_username, imc_password)
    url = f"https://{imc_base_url}:8443/imcrs/plat/res/device/allMsg/{ip}"
    payload = {}
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.get(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        return eval(response.content)


def get_single_device_asset_info(hostname, imc_username, imc_password, imc_base_url="<IMC_FQDN>"):
    """

    Args:
        hostname:
        imc_username:
        imc_password:
        imc_base_url:

    Returns:

    """
    auth = HTTPDigestAuth(imc_username, imc_password)
    phy_class = "3"  # = standalone device
    url = \
        f"https://{imc_base_url}:8443/imcrs/netasset/asset?assetPhyClass={phy_class}&" \
        f"assetDevice.name={hostname}&start=0&size=100&total=false"
    payload = {}
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'
               }
    response = requests.get(url, headers=headers, data=payload, auth=auth, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        return eval(response.content)


def imc_keyring_login(imc_username, keyring_username):
    """

    Args:
        imc_username: str()
        keyring_username: str()

    Returns:
    auth token for IMC login/API calls

    """

    credentials = keyring.get_credential(keyring_username, imc_username)
    imc_user = credentials.username
    imc_pass = credentials.password
    auth = IMCAuth(
        h_url=h_url,
        server=h_url + imc_server,
        port=imc_port,
        username=imc_user,
        password=imc_pass
    )
    return auth


def get_confirmed_alerts_down_hosts(imc_username, imc_password):
    """
    ackStatus=1 = Acknowledged
    alarmLevel=1 = Critical
    recStatus = 0 = Unrecovered
    size=150 = number of entries to get
    alarmCategory=2 = Device Availability Alarm
    """
    ack_status = "1"
    alarm_level = "1"
    recovery_status = "0"
    alarm_category = "2"

    url = f"https://<IMC_FQDN>:8443/imcrs/fault/alarm?operatorName={imc_username}" \
          f"&size=150&alarmLevel={alarm_level}&ackStatus={ack_status}&recStatus={recovery_status}" \
          f"&alarmCategory={alarm_category}"
    payload = {}
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept-encoding': 'application/json'}
    auth = HTTPDigestAuth(imc_username, imc_password)
    response = requests.get(url, headers=headers, auth=auth, data=payload, verify=False)
    response.raise_for_status()
    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print("Error getting Alarms at IMC")
        sys.exit()
