# -*- coding: utf-8 -*-
"""Module to interact with the Ruckus SmartZone API.

inspired from source: https://github.com/commscope-ruckus/The-Kennel


"""
import json
import warnings
# Maybe using a dataclass?:
from dataclasses import dataclass

# imports:
import requests

# import host variable from calling scripts:
from config.ruckus_params import host, http_port


@dataclass
class ApZone:
    """
    dataclass for storing Access Point Zone related data
    """
    zone_name: str = None  #: zone name
    zone_id: str = None  #: zone ID
    zone_details = dict()  #: (dict) zone details
    ap_groups = list()  #: (list) AP groups


@dataclass
class WlanZone:
    """
    dataclass for storing WLAN Zone related data
    """
    zone_name: str
    zone_id: str
    group_name: str
    group_id: str


# global vars:
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
api_base_url: str = "/wsg/api/public/v9_1/"  #: base url of the SmartZone API
service_ticket_query: str = "&serviceTicket="
"""url service ticket portion as QUERY
 Example:
    /wsg/api/public/v9_0/rkszones?listSize=500&serviceTicket=token"""
service_ticket_uri = "?serviceTicket="  #: url service ticket portion as URI
host_url = host
"""host base url of the SmartZone
 Example:
    https://wlc.domain.com"""

ruckus_wlc_url = f"https://{host_url}:{http_port}"
"""complete base URL for the API call
 Example:
    https://wlc.domain.com:8443"""

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}


def set_ap_zone_data(token) -> list:
    """ get the current AP zones from a Ruckus WLC/SmartZone

    :param token: authentication token from Ruckus API call
    :return: list of access point zones
    """
    api_specific_url = f"rkszones?listSize=500"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_query}{token}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    response_json = response.json()['list']
    zone_list = list()
    for zone in response_json:
        if zone['name'] != 'Staging Zone':
            zone_details = query_specific_zone(zone_id=zone['id'], token=token)
            ap_zone = ApZone(zone_name=zone['name'], zone_id=zone['id'])
            ap_groups = query_ap_groups(zone['id'], token)
            ap_zone.zone_details = zone_details
            ap_zone.ap_groups = ap_groups
            for ap in ap_zone.ap_groups:
                ap_status_online_count = query_online_ap_status(ap['id'], token)
                online_count = {"online_device_count": ap_status_online_count}
                ap.update(online_count)
                ap_status_offline_count = query_offline_ap_status(ap['id'], token)
                offline_count = {"offline_device_count": ap_status_offline_count}
                ap.update(offline_count)
                ap_status_offline_names = query_offline_ap_status(ap['id'], token)[1]
                ap_offline_name_list = {"offline_device_names": ap_status_offline_names}
                ap.update(ap_offline_name_list)
                ap_status_flagged_count = query_flagged_ap_status(ap['id'], token)
                flagged_count = {"flagged_device_count": ap_status_flagged_count}
                ap.update(flagged_count)
                total_ap_count = ap_status_online_count + ap_status_offline_count + ap_status_flagged_count
                sum_ap_count = {"total_ap_count": total_ap_count}
                ap.update(sum_ap_count)
            zone_list.append(ap_zone)
    return zone_list


def create_specific_ap_zone(affected_ap_zone: str, token: str) -> list:
    """

    Args:
        affected_ap_zone: AP zone ID
        token: authentication token

    Returns:


    """
    api_specific_url = f"rkszones?listSize=500"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_query}{token}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    response_json = response.json()['list']
    zone_list = list()
    for zone in response_json:
        if zone['name'].lower() != 'staging zone' and zone['name'].lower() == affected_ap_zone.lower():
            zone_details = query_specific_zone(zone_id=zone['id'], token=token)
            ap_zone = ApZone(zone_name=zone['name'], zone_id=zone['id'])
            ap_groups = query_ap_groups(zone['id'], token)
            ap_zone.zone_details = zone_details
            ap_zone.ap_groups = ap_groups
            for ap in ap_zone.ap_groups:
                ap_status_online_count = query_online_ap_status(ap['id'], token)
                online_count = {"online_device_count": ap_status_online_count}
                ap.update(online_count)
                #
                ap_status_offline_count = query_offline_ap_status(ap['id'], token)[0]
                offline_count = {"offline_device_count": ap_status_offline_count}
                ap.update(offline_count)
                #
                ap_status_offline_names = query_offline_ap_status(ap['id'], token)[1]
                ap_offline_name_list = {"offline_device_names": ap_status_offline_names}
                ap.update(ap_offline_name_list)
                #
                ap_status_flagged_count = query_flagged_ap_status(ap['id'], token)
                flagged_count = {"flagged_device_count": ap_status_flagged_count}
                ap.update(flagged_count)
                #
                total_ap_count = ap_status_online_count + ap_status_offline_count + ap_status_flagged_count
                sum_ap_count = {"total_ap_count": total_ap_count}
                ap.update(sum_ap_count)
            zone_list.append(ap_zone)
    return zone_list


def get_token(username, password):
    """

    Args:
        username:
        password:

    Returns:
        authentication token

    """
    api_specific_url = f"serviceTicket"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}"
    body = {'username': username, 'password': password}
    r = requests.post(url, json=body, verify=False)
    token = r.json()['serviceTicket']
    return token


def create_new_ap_hostname(country_code, ap_macs: list(), mgmt_subnet: str) -> dict:
    """
    "WAP<COUNTRY_CODE><2nd_OCTET>3rd_OCTET>_<ascending index starting from 001>"
    start index will be the lowest management IP address

    Args:
        mgmt_subnet: IP network portion (without prefix)
        ap_macs: list of MAC addresses of the new Access Points
        country_code: country code of the destination country

    Returns:
        hostname: list with hostnames based on the defined standard

    Example:
        create_new_ap_hostname("<ISO_COUNTRY_CODE", [MAC_1, MAC_2], "172.16.30.0")
    """
    new_hostname = dict()
    for idx, mac in enumerate(ap_macs, start=1):
        temp_ip = mgmt_subnet.split(".")
        temp_2nd_3rd_octet = f'{temp_ip[1].zfill(3)}{temp_ip[2].zfill(3)}'
        temp_hostname = f'WAP{country_code}{temp_2nd_3rd_octet}_{str(idx).zfill(3)}'
        new_hostname.update({temp_hostname: mac})
    return new_hostname


def rename_ap(new_hostname: dict(), token):
    """

    Args:
        new_hostname:
        token:

    Returns:

    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    for hostname, mac in new_hostname.items():
        payload = json.dumps(
            {
                "name": hostname
            }
        )
        api_specific_url = f"aps/{mac}"
        url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
        response = requests.patch(url, data=payload, headers=headers, verify=False)
        response.raise_for_status()


def retrieve_specific_ap_list(zone_id: str(), token):
    """

    Returns:
    list of mac addresses from the APs, that belongs to a specific AP zone
    """
    api_specific_url = f"aps?listSize=500&zoneId={zone_id}"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_query}{token}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    ap_macs = list()
    for item in response.json()['list']:
        ap_macs.append(item['mac'])
    return ap_macs


def get_guest_passes(token, filter_display_name=None):
    """

    Args:

    Returns:
    the current configured guest passes

    Example:
    https://<WLC_FQDN>:8443/wsg/api/public/v9_1/identity/guestpass?serviceTicket=
    """
    api_specific_url = f"identity/guestpass"
    if filter_display_name:
        filter_url = f"&displayName={filter_display_name}"
        url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}{filter_url}"
    else:
        url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()


def get_zones(token):
    """

    Args:
        token:

    Returns:

    """
    api_specific_url = f"rkszones?listSize=500"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_query}{token}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    return response.json()['list']


def get_specific_zone(zone_name: str, get_zones_results: list):
    for zone in get_zones_results:
        if zone['name'] == zone_name:
            result = zone
            return result


def query_specific_zone(zone_id, token):
    api_specific_url = f"rkszones/{zone_id}"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    return response.json()


def query_ap_groups(zone_id, token):
    """
    Use this API command to retrieve the list of AP groups that belong to a zone.

    URL: https://wlc.acme.com:8443/wsg/api/public/v9_1/rkszones/{zone_id}/apgroups?serviceTicket=

    Returns:

    """
    api_specific_url = f"rkszones/{zone_id}/apgroups"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    return response.json()['list']


def query_online_ap_status(ap_group_id: str, token: str):
    """


    Args:
        ap_group_id: str
        token: str

    Returns:
    total count of online APs per specific AP zone
    """

    payload = json.dumps({
        "filters": [
            {
                "type": "APGROUP",
                "value": ap_group_id,
                "operator": "eq"

            },
        ],
        "extraFilters": [
            {
                "type": "SYNCEDSTATUS",
                "value": "Online",
                "operator": "eq"
            }
        ]
    })
    api_specific_url = f"query/ap"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.post(url, data=payload, headers=headers, verify=False)
    response.raise_for_status()
    total_count_online_aps = response.json()['totalCount']
    return total_count_online_aps


def query_offline_ap_status(ap_group_id: str, token: str):
    """


    Args:
        ap_group_id: str
        token: str

    Returns:
    total count of offline APs per specific AP zone
    """
    payload = json.dumps({
        "filters": [
            {
                "type": "APGROUP",
                "value": ap_group_id,
                "operator": "eq"

            },
        ],
        "extraFilters": [
            {
                "type": "SYNCEDSTATUS",
                "value": "Offline",
                "operator": "eq"
            }
        ]
    })
    api_specific_url = f"query/ap"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.post(url, data=payload, headers=headers, verify=False)
    response.raise_for_status()
    total_count_offline_aps = response.json()['totalCount']
    offline_aps_names = offline_ap_processing(response.json()['list'])
    return total_count_offline_aps, offline_aps_names


def offline_ap_processing(offline_aps: list):
    """

    Args:
        offline_aps: list of offline APs from response.json()['list']

    Returns:
    list with offline AP name
    """
    offline_aps_device_names = list()
    for offline_ap in offline_aps:
        device_data = f"Hostname: <{offline_ap.get('deviceName')}> / " \
                      f"MAC: <{offline_ap.get('apMac')}> / IP: <{offline_ap.get('ip')}>"
        offline_aps_device_names.append(device_data)
    return offline_aps_device_names


def query_flagged_ap_status(ap_group_id: str, token: str):
    """


    Args:
        ap_group_id: str
        token: str

    Returns:
    total count of offline APs per specific AP zone
    """

    payload = json.dumps({
        "filters": [
            {
                "type": "APGROUP",
                "value": ap_group_id,
                "operator": "eq"

            },
        ],
        "extraFilters": [
            {
                "type": "SYNCEDSTATUS",
                "value": "Flagged",
                "operator": "eq"
            }
        ]
    })
    api_specific_url = f"query/ap"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.post(url, data=payload, headers=headers, verify=False)
    response.raise_for_status()
    total_count_flagged_aps = response.json()['totalCount']
    return total_count_flagged_aps


def query_client_count_ap_group(ap_group_id: str, token: str):
    """


    Args:
        ap_group_id: str
        token: str

    Returns:
    client count per specific AP group
    """
    payload = json.dumps({
        "filters": [
            {
                "type": "APGROUP",
                "value": ap_group_id,
                "operator": "eq"

            }
        ]
    })
    api_specific_url = f"query/client"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    response = requests.post(url, data=payload, headers=headers, verify=False)
    response.raise_for_status()
    total_client_count_ap_group = response.json()['totalCount']
    return total_client_count_ap_group


def upgrade_zone_firmware(zone_id: str,
                          current_zone_fw: str,
                          required_firmware: str,
                          token: str,
                          dry_run_flag: bool,
                          zone_name: str
                          ):
    """
    Args:
        zone_name:
        current_zone_fw:
        dry_run_flag: if True then only print out a meaningful msg at the upgrade part
        required_firmware:
        zone_id: 
        token: 

    Returns:

    """
    api_specific_url = f"rkszones/{zone_id}/apFirmware"
    url = f"{ruckus_wlc_url}{api_base_url}{api_specific_url}{service_ticket_uri}{token}"
    # url = \
    #   "https://" + host + ":8443" + "/wsg/api/public/v9_0/rkszones/" + zoneID + "/apFirmware?serviceTicket=" + token
    if dry_run_flag:
        return "This was only a test run! No firmware was upgraded/changed"
    elif not dry_run_flag and current_zone_fw == required_firmware:
        return f"Firmware already meets the desired version of: {required_firmware}"
    elif not dry_run_flag and current_zone_fw != required_firmware:
        body = {
            "firmwareVersion": required_firmware
        }
        response = requests.put(url, json=body, verify=False)
        response.raise_for_status()
        if response.status_code == 204:
            msg = f"Change of AP zone version to: {required_firmware} was successfully triggered! " \
                  f"Please wait the corresponding time and check, " \
                  f'if the AP zone: "{zone_name}" is functional again...'
            # r = 204 #comment out this line and uncomment the previous to really make the upgrade
            return msg
