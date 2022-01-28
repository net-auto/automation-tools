# --------------------------------PRTG functions:-------------------------------------------------------
#
import logging
from ipaddress import IPv4Address, IPv4Network, AddressValueError

import requests
from requests import Response

from classes.prtg import prtg
from classes.prtg.prtg import prtg_api, prtg_device
from config.prtg_params import prtg_host, prtg_port, prtg_protocol


def add_prtg_data(prtg_objects, imc_device_inventory: dict) -> None:
    # switch_inventory = list()
    # prtg_objects = get_prtg_all_objects(device, prtg_username, prtg_passhash)
    prtg_alldevices = prtg_objects.alldevices
    # create an IP list from prtg_alldevices for checking the monitoring status:
    prtg_hosts = list()
    for device in prtg_alldevices:
        # only IPv4 addresses as host IP will be processed:
        try:
            prtg_ipv4 = IPv4Address(device.host)
            prtg_hosts.append(prtg_ipv4)
        except AddressValueError as address_error:
            # print(address_error)
            pass

    # check/add monitored flag to the corresponding IP/device:
    for imc_device_ipv4, imc_class_obj in imc_device_inventory.items():
        if imc_device_ipv4 in prtg_hosts:
            # print(imc_device_ipv4)
            imc_class_obj.prtg_monitored = True
        else:
            imc_class_obj.prtg_monitored = False


def create_dummy_data(prtg_objects) -> dict:
    dummy_inventory = dict()
    # add dummy devices to inventory:
    for device in prtg_objects.alldevices:
        if "DUMMY" in device.name:
            ipv4_prefix = IPv4Network(device.host)
            dummy_temp_inventory = \
                {
                    'prtg_id': device.id,
                    'hostname': device.name,
                    'ipv4_prefix': ipv4_prefix
                }
            for group in prtg_objects.allgroups:
                for member in group.devices:
                    if device.id == member.id:
                        dummy_temp_inventory.update({'prtg_parent_id': group.id})
            dummy_inventory.update({ipv4_prefix: dummy_temp_inventory})
    return dummy_inventory


def check_dummy_existence(imc_device_inventory, prtg_dummy_devices) -> dict:
    """
        check if dummy IPv4 prefix exists for the missing devices and add "prtg_dummy_exists" flag
        also adds the dummy parent ID to the ones with existing dummy / IPv4 prefix
    Args:
        imc_device_inventory:
        prtg_dummy_devices:

    Returns:
        new dict with the devices that has a valid IPv4 dummy prefix at PRTG
    """
    # create list of IPv4Networks from prtg_dummy_devices keys:
    missing_devices = dict()
    dummy_ipv4_prefixes = list(prtg_dummy_devices)
    for imc_device_ipv4, imc_device_data in imc_device_inventory.items():
        if not imc_device_data.prtg_monitored:
            check_result = [
                dummy_prefix  # expression
                for dummy_prefix in dummy_ipv4_prefixes  # item in iterable
                if imc_device_ipv4 in dummy_prefix  # condition
            ]
            # print(check_result)
            if not check_result:
                imc_device_data.prtg_dummy_exists = False
            else:
                imc_device_data.prtg_dummy_exists = True
                imc_device_data.dummy_parent_id = \
                    prtg_dummy_devices[check_result[0]].get('prtg_parent_id')
                imc_device_data.dummy_prtg_id = \
                    prtg_dummy_devices[check_result[0]].get('prtg_id')

            # add the missing devices with the updated parameters to the result dict()
            missing_devices.update({imc_device_ipv4: imc_device_data})

    return missing_devices


def get_prtg_all_objects(prtg_user, prtg_passhash):
    """
    get all devices/hosts from PRTG and return a dict with the devices, groups objects
    """
    prtg_objects = prtg_api(
        host=prtg_host, user=prtg_user,
        passhash=prtg_passhash, protocol='https', port='443'
    )
    return prtg_objects


def get_prtg_single_device(ipv4_dev_ip, prtg_devices: dict):
    for device in prtg_devices:
        try:
            if ipv4_dev_ip == IPv4Address(device.host):
                single_device_obj = device
                return single_device_obj
        except AddressValueError:
            pass


def get_prtg_device_snmp_traffic_sensors(prtg_single_device_obj):
    """
    return "SNMP Traffic" sensors from a single device
    """
    all_sensors = prtg_single_device_obj.sensors
    snmp_sensors = list()
    for sensor in all_sensors:
        if str(sensor.sensortype) == "SNMP Traffic":
            snmp_sensors.append(sensor)
    return snmp_sensors


def trigger_auto_discovery_with_template(device_id, prtg_username, prtg_passhash, template):
    """
    triggers an auto-discovery with based an a given template
    """
    payload = {}
    headers = {}
    url = \
        f'https://<PRTG_FQDN>/api/discovernow.htm?id=' \
        f'{device_id}&template=\"{template}\"&username={prtg_username}&passhash={prtg_passhash}'
    response: Response = requests.get(url, headers=headers, data=payload)
    return response


def delete_sensor_by_id(prtg_single_device_obj, sensor_id):
    """
    deletes a sensor by his ID
    ATTENTION:
    deletion occurs with confirmation! -> Please perform a
    double check for the right sensor ID
    """
    for sensor in prtg_single_device_obj.sensors:
        if sensor.id == sensor_id:
            sensor.delete(confirm=False)


def check_device_at_prtg(ipv4_dev_ip, prtg_devices: dict):
    """
    check if device exsists at PRTG and returns:
    True = if exists
    False = if not exists
    """
    for ip in prtg_devices:
        try:
            if ipv4_dev_ip == IPv4Address(ip.host):
                # print("DEVICE FOUND AT PRTG")
                device_exists = True
                # print(device_exists)
                return device_exists
        except KeyError:
            # skip missing device and return false
            device_exists = False
            return device_exists
            pass


def delete_prtg_device(prtg_single_device_obj):
    """
    deletes the host at PRTG WITHOUT confirmation
    """
    result = prtg_single_device_obj.delete(confirm=False)
    return result


def triggerSnmpTrafficAutoDiscoveryMpls(deviceId, PRTG_USER, PRTG_PWHASH):
    url = \
        f"https://<PRTG_FQDN>/api/discovernow.htm?id=" \
        f"{deviceId}&template=\"SNMP_TRAFFIC_ERR_DIS_CONNECTED.odt\"&username={PRTG_USER}&passhash={PRTG_PWHASH}"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    return response


def get_current_down_ping_sensors(prtg_user, prtg_passhash):
    """
    Conditions:
    - Sensor (ping) must be in down state
    -
    """
    url = \
        f"https://<PRTG_FQDN>/api/table.json?filter_status=5&filter_type=ping&content=sensors&columns=" \
        f"objid,device,sensor,status,message,parentid&username={prtg_user}&passhash={prtg_passhash}"
    payload = {}
    headers = {}
    response = requests.get(url, headers=headers, data=payload)
    down_ping_sensors = eval(response.text)["sensors"]
    return down_ping_sensors


def get_single_device_obj(prtg_host, prtg_user, prtg_passhash, device_id):
    device = prtg.prtg_device(prtg_host, prtg_user, prtg_passhash, device_id, protocol="https", port="443")
    return device


def ack_alarm(prtg_user, prtg_passhash, sensor_id, ack_user_name: str):
    """
    Comment written at PRTG Alarm: ACK_FROM_IMC
    """
    # comment = f'acknowledged by: IMC'
    comment = f'acknowledged by: {ack_user_name}'
    url = f'https://<PRTG_FQDN>/api/acknowledgealarm.htm?id={sensor_id}&ackmsg=' \
          f'{comment}&username={prtg_user}&passhash={prtg_passhash}'
    payload = {}
    headers = {}
    response = requests.get(url, headers=headers, data=payload)
    return response


def get_existing_dummy_devices(prtg_devices):
    """
    get the current dummy devices/networks from the prtg_devices list
    """
    dummy_devices = dict()
    # iterate through allDevices = index 0
    for dummy in prtg_devices:
        if 'DUMMY_ACCESS' in dummy.name:
            dummy_devices.update({IPv4Network(dummy.host): dummy})
    return dummy_devices


def compute_missing_devices_at_prtg(imc_switch_objects: dict, prtg_objects_dict: dict):
    missing_devices = dict()
    for ipv4, imc_sw_obj in imc_switch_objects.items():
        if str(IPv4Address(ipv4)) not in prtg_objects_dict:
            missing_devices.update({ipv4: imc_sw_obj})
    return missing_devices


def create_new_device(missing_devices_at_prtg: dict,
                      keyring_username,
                      keyring_passhash,
                      logger_obj) -> None:
    """

    Args:
        logger_obj: logging instance
        keyring_passhash:
        keyring_username:
        missing_devices_at_prtg: key: IPv4Address, value: SwitchInventory object

    Returns:

    """
    for ipv4, switch_data in missing_devices_at_prtg.items():
        if switch_data.prtg_dummy_exists and not switch_data.prtg_already_created:
            # get the dummy device from PRTG as prtg_device object:
            dummy_prtg_device = \
                prtg_device(
                    host=prtg_host,
                    port=prtg_port,
                    user=keyring_username,
                    passhash=keyring_passhash,
                    protocol=prtg_protocol,
                    deviceid=switch_data.dummy_prtg_id
                )
            # print(dummy_prtg_device)
            # clone the dummy device with the missing switch data:
            missing_device_creation_result = \
                dummy_prtg_device.clone(newname=switch_data.hostname,
                                        newAddress=ipv4.compressed,  # IPv4Address as str
                                        newplaceid=switch_data.dummy_parent_id  # parent ID of the dummy object
                                        )
            # print(missing_device_creation_result)
            if missing_device_creation_result.status_code == 200:
                switch_data.prtg_successful_created = True
                logger_obj.info(
                    f'device/switch: "{switch_data.hostname}" with '
                    f'IP: "{ipv4.compressed}" was successfully created at PRTG')
                logger_obj.info(100 * '-')
            else:
                switch_data.prtg_successful_created = False
                logger_obj.info(
                    f'device/switch: "{switch_data.hostname}" with '
                    f'IP: "{ipv4.compressed}" was FAILED to create at PRTG')
                logger_obj.info(100 * '-')


def get_specific_parent_group_object(missing_devices_at_prtg: dict, keyring_username, keyring_passhash) -> dict:
    """
    unique prtg ID will only be saved once. Duplicates will be overwritten

    Args:
        missing_devices_at_prtg:
        keyring_username:
        keyring_passhash:

    Returns:
    specific prtg group object based on the dummy parent ID at the missing_devices dict
    specific_prtg_group:
    key: prtg id
    value: child devices of that group

    """
    specific_prtg_group = dict()
    for ipv4, switch_data in missing_devices_at_prtg.items():
        if switch_data.prtg_dummy_exists:
            prtg_specific_group_of_new_devices = \
                prtg_api(
                    host=prtg_host, user=keyring_username,
                    passhash=keyring_passhash, protocol=prtg_protocol, port=prtg_port,
                    rootid=switch_data.dummy_parent_id
                )
            check_result = [
                ipv4.compressed  # expression
                for missing_ipv4 in prtg_specific_group_of_new_devices.alldevices  # item in iterable
                if ipv4.compressed == missing_ipv4.host  # condition
            ]
            if check_result:
                switch_data.prtg_already_created = True
            else:
                switch_data.prtg_already_created = False
            specific_prtg_group.update(
                {prtg_specific_group_of_new_devices.id: prtg_specific_group_of_new_devices})
    return specific_prtg_group


def refresh_missing_group(specific_missing_devices_groups: dict,
                          keyring_username,
                          keyring_password) -> None:
    for device_group_id, device_group_object in specific_missing_devices_groups.items():
        group_to_refresh = prtg_api(
            host=prtg_host, user=keyring_username,
            passhash=keyring_password, protocol=prtg_protocol, port=prtg_port,
            rootid=device_group_id
        )
        specific_missing_devices_groups.update({device_group_id: group_to_refresh})


def resume_new_created_hosts(missing_devices_at_prtg: dict, logger_obj: logging) -> None:
    """

    Args:
        logger_obj: logging instance
        missing_devices_at_prtg:

    Returns:
        None
    """

    for ipv4, switch_data in missing_devices_at_prtg.items():
        if hasattr(switch_data, 'prtg_device_object'):
            if str(switch_data.prtg_device_object.active) == 'false':
                resume_status = switch_data.prtg_device_object.resume()
                if resume_status.status_code == 200:
                    switch_data.prtg_successfully_resumed = True
                    logger_obj.info(
                        f'device/switch: "{switch_data.hostname}" with '
                        f'IP: "{switch_data.ip_address.compressed}" '
                        f'was resumed at PRTG and is now being monitored')
                    logger_obj.info(100 * '-')
                else:
                    switch_data.prtg_successfully_resumed = False
                    logger_obj.info(
                        f'device/switch: "{switch_data.hostname}" with '
                        f'IP: "{switch_data.ip_address.compressed}" '
                        f'was FAILED to resume at PRTG')
                    logger_obj.info(100 * '-')


def check_new_device(prtg_object, missing_devices_at_prtg: dict, logging_obj):
    """
    check if new devices was created and assign the bool attribute: prtg_device_active
    at the corresponding switch object
    """
    prtg_devices = prtg_object.alldevices
    prtg_host_status = dict()
    for device in prtg_devices:
        prtg_host_status.update({device.host: bool(device.active)})

    for ipv4 in missing_devices_at_prtg:
        status = prtg_host_status.get(ipv4.compressed)
        if status and missing_devices_at_prtg[ipv4].prtg_new_device_created:
            missing_devices_at_prtg[ipv4].prtg_device_active = True
            """
            logging_obj.info(f'The host with the IP: {ipv4.compressed} was created and is now active at PRTG')
            logging_obj.info(100 * '-')
            """
        elif not status and missing_devices_at_prtg[ipv4].prtg_ipv4_prefix_exists:
            missing_devices_at_prtg[ipv4].prtg_device_active = False
            logging_obj.warning(
                f'The host with the IP: {ipv4.compressed} is still paused at PRTG. Please check the host at PRTG')
            logging_obj.info(100 * '-')


def update_prtg_devices(prtg_devices):
    new_prtg_devices = dict()
    for prtg_device_obj in prtg_devices:
        new_prtg_devices.update({prtg_device_obj.host: prtg_device_obj})
    return new_prtg_devices


def update_device_object(specific_missing_devices_groups: dict, missing_devices: dict) -> None:
    """

    Args:
        specific_missing_devices_groups:
        missing_devices:

    Returns:
        None

    """
    for ipv4, switch_data in missing_devices.items():
        for group_id, devices_data in specific_missing_devices_groups.items():
            if hasattr(switch_data, 'dummy_parent_id') and \
                    str(switch_data.dummy_parent_id) == str(group_id):
                for device in devices_data.devices:
                    if str(device.host) == ipv4.compressed:
                        switch_data.prtg_device_object = device
