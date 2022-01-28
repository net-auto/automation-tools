"""
IMC RestAPI availability needed!

functions to be used with:
- netmiko
- textfsm
- ntc-templates
device_type is set to: 'hp_comware'

please get the ntc-templates in a different folder via git clone and set
the environment variable: "NET_TEXTFSM" to the templates folder (where the index file is located)
"""
from collections import defaultdict
from ipaddress import IPv4Address, AddressValueError, IPv4Network, IPv4Interface
from pathlib import Path

import flatdict
from mac_vendor_lookup import MacLookup, BaseMacLookup
from netmiko import Netmiko, NetmikoAuthenticationException
from netmiko.ssh_dispatcher import ConnectHandler

from modules import imc


# classes:
class Switch:
    """
    test with own switch class
    """

    def __init__(self, ipv4: IPv4Address):
        self.lldp_neighbors = None
        self.ip_address = ipv4
        self.hostname = None
        self.imc_id = None
        self.lldp_neighbors = None
        self.is_root_neighbor = False
        self.hop_count = None
        self.dhcp_snooping_intf = None
        self.dynamic_mac_count = None
        self.ntp_status = None
        self.subnet_mask = None
        self.ipv4_prefix = None
        self.platform = None
        self.sw_version = None
        self.asset_count = None
        self.sku = None
        self.device_name = None
        self.prtg_new_device_created = None

    def set_details_from_imc(self, imc_username, imc_password):
        imc_single_device_details = \
            imc.get_single_device_info(
                self.ip_address.compressed, imc_username=imc_username, imc_password=imc_password
            )
        self.imc_id = imc_single_device_details['id']
        self.subnet_mask = imc_single_device_details['mask']
        self.platform = set_platform(imc_single_device_details['sysDescription'])
        self.hostname = imc_single_device_details['sysName']
        self.sku = imc_single_device_details['typeName']
        self.device_name = imc_single_device_details['deviceSeries']['name']
        self.ipv4_prefix = IPv4Interface(
            f'{self.ip_address.compressed}/{self.subnet_mask}').network

    def set_asset_details_from_imc(self, imc_username, imc_password):
        imc_single_device_asset_info = \
            imc.get_single_device_asset_info(self.hostname, imc_username=imc_username,
                                             imc_password=imc_password)
        self.asset_count = len(imc_single_device_asset_info['netAsset'])
        self.sw_version = imc_single_device_asset_info['netAsset'][0]['softVersion']

    def get_lldp_neighbors(self, username: str, password: str):
        """
        Comware 7 and Comware 5 supported
        """
        cw7_lldp_neigh_verbose_cmd = 'display lldp neighbor-information verbose'
        cw5_lldp_neigh_cmd = 'display lldp neighbor-information'
        net_connect = Netmiko(
            host=str(self.ip_address), username=username, password=password, device_type='hp_comware')
        lldp_neighbor_result = net_connect.send_command(cw7_lldp_neigh_verbose_cmd, use_textfsm=True)
        #
        # save cw5 result:
        if "Too many parameters found" in lldp_neighbor_result:
            lldp_neighbor_result = net_connect.send_command(cw5_lldp_neigh_cmd, use_textfsm=True)
            self.lldp_neighbors = lldp_neighbor_result
        #
        # save cw7 result:
        self.lldp_neighbors = lldp_neighbor_result
        # disconnect from device:
        net_connect.disconnect()

    def check_if_root_neighbor(self, root_device_ip: str):
        """
        if root switch is listed in the lldp_neighbors, then set to: True
        """
        for neighbor in self.lldp_neighbors:
            if neighbor["management_ip"] == root_device_ip:
                self.is_root_neighbor = True
                self.hop_count = 0
                # neighbor.update({'hop_count': 0})

    def set_hop_count(self, hop_count: dict, root_device_ip: str):
        """
        set hop count that shows the distance to the root device
        """
        if self.ip_address != IPv4Address(root_device_ip) and self.hop_count == 0:
            for neighbor in self.lldp_neighbors:
                try:
                    # while not hop_count[IPv4Address(neighbor["management_ip"])]:
                    # if IPv4Address(neighbor['management_ip']) != IPv4Address(root_device_ip):
                    # print("hop_count value:", hop_count[IPv4Address(neighbor["management_ip"])])
                    if IPv4Address(neighbor['management_ip']) != IPv4Address(root_device_ip):
                        neighbor.update({'hop_count': 1})
                    """
                    if neighbor['hop_count'] == 0:
                        neighbor.update({'hop_count': 1})
                    if hop_count[IPv4Address(neighbor["management_ip"])] == 1:
                        self.hop_count = 2
                    if hop_count[IPv4Address(neighbor["management_ip"])] == 2:
                        self.hop_count = 3
                    if hop_count[IPv4Address(neighbor["management_ip"])] == 3:
                        self.hop_count = 4
                    """
                except KeyError as e:
                    # skip if corresponding key is not found in lldp_neighbor
                    print("KeyError:", e)
                    pass

    def set_dhcp_snooping_interfaces(self, root_device_ip: str, imc_devices: dict):
        interfaces = defaultdict()
        #
        # resolve MAC address in  management_ip field
        # needed for some older Comware releases
        resolve_mac_to_mgmt_ip(self.lldp_neighbors, imc_devices)
        #
        for neighbor in self.lldp_neighbors:
            if IPv4Address(neighbor['management_ip']) in imc_devices:
                if self.ip_address == IPv4Address(root_device_ip):
                    interfaces.update({neighbor['local_interface']: self.ip_address})
                elif self.is_root_neighbor and \
                        IPv4Address(neighbor['management_ip']) != IPv4Address(root_device_ip):
                    interfaces.update({neighbor['local_interface']: self.ip_address})
                elif not self.is_root_neighbor and \
                        IPv4Address(neighbor['management_ip']) != IPv4Address(root_device_ip):
                    interfaces.update({neighbor['neighbor_port_id']: IPv4Address(neighbor['management_ip'])})
        #
        self.dhcp_snooping_intf = interfaces

    def get_dynamic_mac_count(self, username: str, password: str):
        """

        """
        dynamic_mac_count_cmd = 'display mac-address dynamic count'
        ip_address_as_string = str(IPv4Address(self.ip_address))
        ttp_template_path = \
            Path.cwd() / "tools" / "ttp-templates" / "hp_comware_display_mac-address_dynamic_count.ttp"
        remote_device = {
            'device_type': 'hp_comware',
            'host': ip_address_as_string,
            'username': username,
            "conn_timeout": 5,
            'password': password
        }
        try:
            net_connect = \
                ConnectHandler(**remote_device)
        except ValueError:
            # try device_type: hp_procurve, if hp_comware has failed:
            # example: needed for the 2530 switches
            remote_device['device_type'] = 'hp_procurve'
            net_connect = \
                ConnectHandler(**remote_device)

        dynamic_mac_count_result = \
            net_connect.send_command(
                dynamic_mac_count_cmd, use_ttp=True, ttp_template=ttp_template_path.read_text())[0][0]
        net_connect.disconnect()
        if dynamic_mac_count_result:
            result_flatted = flatdict.FlatDict(dynamic_mac_count_result)
            self.dynamic_mac_count = int(result_flatted.values()[0])
        else:
            self.dynamic_mac_count = 'CMD was not successful'
        """
        except AuthenticationException:
            print(f'Authentication Failure for switch: {ip_address_as_string}')
            pass
        except ValueError as value_err:
            print(f'Value error: {value_err}')
            pass
        """

    def get_ntp_status_ttp(self, username: str, password: str):
        """

        """
        ntp_status_cmd = 'display ntp status'
        ip_address_as_string = self.ip_address.compressed
        ttp_template_path = \
            Path.cwd() / "tools" / "ttp-templates" / "hp_comware_display_ntp_status.ttp"
        remote_device = {
            'device_type': 'hp_comware',
            'host': ip_address_as_string,
            'username': username,
            "conn_timeout": 2,
            'password': password
        }
        try:
            net_connect = \
                ConnectHandler(**remote_device)
        except ValueError:
            # try device_type: hp_procurve, if hp_comware has failed:
            # example: needed for the 2530 switches
            ntp_status_cmd = 'show ntp status'
            remote_device['device_type'] = 'hp_procurve'
            net_connect = ConnectHandler(**remote_device)

        ntp_status_results = \
            net_connect.send_command(
                ntp_status_cmd, use_ttp=True, ttp_template=ttp_template_path.read_text()
            )[0][0]
        net_connect.disconnect()
        if ntp_status_results:
            result_flatted = flatdict.FlatDict(ntp_status_results)
            self.ntp_status = result_flatted.values()[0]
        else:
            self.ntp_status = 'CMD was not successful'


# static functions:
def set_platform(sys_description):
    platform = str()
    if isinstance(sys_description, str):
        if 'version 7' in sys_description.lower():
            platform = 'cw7'
        if 'version 5' in sys_description.lower():
            platform = 'cw5'
        if '2530' in sys_description.lower():
            platform = '2530'
        return platform
    else:
        platform = 'unknown/no sysDesc available'
        return platform


def remove_duplicated_values_from_dict(dict_input):
    temp_dict_one_result = {val: key for key, val in dict_input.items()}
    final_result = {val: key for key, val in temp_dict_one_result.items()}
    return final_result


def create_interface_list_from_dict(dict_input):
    temp_list = list()
    for key, value in dict_input.items():
        temp_list.append(value)
    return temp_list


def get_lldp_neighbor(host_ip_address: str, username: str, password: str):
    """
    Comware 7 and Comware 5 supported
    """
    cw7_lldp_neigh_verbose_cmd = 'display lldp neighbor-information verbose'
    cw5_lldp_neigh_cmd = 'display lldp neighbor-information'
    net_connect = Netmiko(host=host_ip_address, username=username, password=password, device_type='hp_comware')
    lldp_neighbor_result = net_connect.send_command(cw7_lldp_neigh_verbose_cmd, use_textfsm=True)
    if "Too many parameters found" in lldp_neighbor_result:
        lldp_neighbor_result = net_connect.send_command(cw5_lldp_neigh_cmd, use_textfsm=True)
        return lldp_neighbor_result
    net_connect.disconnect()
    return lldp_neighbor_result


def get_mac_table(host_ip_address: str, username: str, password: str):
    """
    get the mac address-table for Comware 7 devices via textfsm
    """
    cw7_display_mac_address_cmd = 'display mac-address'
    print(f'GETTING MAC_TABLE OF SWITCH: "{host_ip_address}"....')
    try:
        net_connect = Netmiko(host=host_ip_address,
                              username=username,
                              password=password,
                              device_type='hp_comware')
    except NetmikoAuthenticationException as auth_error:
        print(f'Could not authenticate / connect to switch: {host_ip_address}')
        print('skipping this switch...')
        return 'AUTHENTICATION FAILED'
        pass

    cw7_display_mac_address_result = net_connect.send_command_timing(cw7_display_mac_address_cmd, use_textfsm=True)
    """
    if "Too many parameters found" in lldp_neighbor_result:
        lldp_neighbor_result = net_connect.send_command(cw5_lldp_neigh_cmd, use_textfsm=True)
        return lldp_neighbor_result
    """
    print(f'GOT MAC_TABLE OF SWITCH: "{host_ip_address}"')
    net_connect.disconnect()
    return cw7_display_mac_address_result


def resolve_ruckus_mac_oid(imc_device_inventory: dict) -> None:
    """
    pass imc_device_inventory with mac table already set
    only edge ports will be added -> no (XGE) TenGig or (BAGG) LACP interfaces!
    Args:
        imc_device_inventory:

    Returns:

    """
    # refresh mac vendor db:
    mac_vendor_path = Path('mac_vendor_db/')
    if not Path.exists(mac_vendor_path):
        Path.mkdir(mac_vendor_path)
    BaseMacLookup.cache_path = mac_vendor_path / "vendors.txt"
    mac_lookup = MacLookup()
    mac_lookup.update_vendors()
    for ipv4, switch_data in imc_device_inventory.items():
        switch_data.ruckus_interfaces = set()
        for mac in switch_data.mac_table:
            try:
                vendor_id = mac_lookup.lookup(mac.get('macaddress'))
            except KeyError as e:
                # print(f'KeyError for: {vendor_id} occurred, but added to result')
                # print(f'Attached interface: {mac.get("interface")}')
                vendor_id = vendor_id
                pass
            if "Ruckus".lower() in str(vendor_id).lower() or \
                    "Commscope".lower() in str(vendor_id).lower():
                if mac.get('interface').startswith('GE'):
                    switch_data.ruckus_interfaces.add(mac.get('interface'))


def get_device_manuinfo(host_ip_address, username, password):
    display_manuinfo_cmd = "display device manuinfo"
    net_connect = Netmiko(host=host_ip_address, username=username, password=password, device_type='hp_comware')
    display_manuinfo_result = net_connect.send_command(display_manuinfo_cmd, use_textfsm=True)
    net_connect.disconnect()
    return display_manuinfo_result


def get_display_arp(host_ip_address, username, password):
    display_arp_cmd = "display arp"
    net_connect = Netmiko(host=host_ip_address, username=username, password=password, device_type='hp_comware')
    display_arp_result = net_connect.send_command(display_arp_cmd, use_textfsm=True)
    net_connect.disconnect()
    return display_arp_result


def check_if_ipv4_rfc_1918(management_ip: str):
    """
    not is_link_local = exclude APIPA addresses (boo)
    is_private = only private address range (bool)
    """
    if not IPv4Address(management_ip).is_link_local and \
            IPv4Address(management_ip).is_private:
        is_ipv4_rfc1918 = True
    else:
        is_ipv4_rfc1918 = False
    return is_ipv4_rfc1918


def check_ipv4_mgmt_ip(management_ip):
    try:
        IPv4Address(management_ip)
        is_ipv4_address = True
        return is_ipv4_address
    except AddressValueError:
        is_ipv4_address = False
        return is_ipv4_address


def set_interface_dhcp_snooping_cfg(host_ip_address, local_interface, username, password):
    set_dhcp_snooping_cfg_set = (f"interface {local_interface}",
                                 "dhcp snooping trust"
                                 )
    net_connect = Netmiko(host=host_ip_address, username=username, password=password, device_type='hp_comware')
    set_dhcp_snooping_if_result = net_connect.send_config_set(set_dhcp_snooping_cfg_set)
    net_connect.disconnect()
    return set_dhcp_snooping_if_result


def get_link_aggregation_members(host_ip_address: str, username: str, password: str):
    ttp_template_path = \
        Path.cwd() / "tools" / "ttp-templates" / "hp_comware_link-aggregation-member-imc_port.ttp"
    display_link_aggr_cmd = "display link-aggregation member-imc_port"
    net_connect = Netmiko(host=host_ip_address, username=username, password=password, device_type='hp_comware')
    display_link_aggr_result = \
        net_connect.send_command(display_link_aggr_cmd, use_ttp=True, ttp_template=ttp_template_path.read_text())[0][0]
    net_connect.disconnect()
    return display_link_aggr_result


def resolve_mac_to_mgmt_ip(device_neighbors, imc_devices_dict):
    # check/replace management_ip field with IPv4Address from imc_devices_dict
    for neighbors in device_neighbors:
        if not check_ipv4_mgmt_ip(neighbors['management_ip']):
            for ipv4_address, hostname_device_id in imc_devices_dict.items():
                if hostname_device_id[0].lower() == neighbors['neighbor'].lower():
                    neighbors['management_ip'] = str(IPv4Address(ipv4_address))


def check_device_if_imc_device(management_ip: str, imc_devices_dict: dict):
    # for neighbors in device_neighbor:
    if IPv4Address(management_ip) in imc_devices_dict:
        # imc_devices_dict[IPv4Address(neighbors['management_ip'])][0].lower() == neighbors['neighbor'].lower():
        is_imc_device = True
    else:
        is_imc_device = False
    return is_imc_device


def root_device_neighbors(root_device: str, exclude_device_list, imc_username: str, imc_password: str):
    print(f"Getting neighbors from root device: {root_device}")
    device_neighbors = get_lldp_neighbor(root_device, imc_username, imc_password)
    print(f"Got neighbors from root device: {root_device}")
    # remove devices based on the excludeDevice list:
    device_neighbors = [neighbor for neighbor in device_neighbors
                        if neighbor["neighbor"] not in exclude_device_list]
    return device_neighbors


def get_additional_neighbors(device_neighbors_dict, imc_devices_dict, exclude_device_list, imc_username, imc_password):
    # resolve mac address in management_ip field :
    resolve_mac_to_mgmt_ip(device_neighbors_dict, imc_devices_dict)
    new_neighbor_ip_list = list()
    temp_result = dict()

    # build IP list with the new neighbors
    # and check if it is a rfc1918 address and not an link_local address:
    for neighbors in device_neighbors_dict:
        if check_if_ipv4_rfc_1918(neighbors['management_ip']) and \
                check_device_if_imc_device(neighbors['management_ip'], imc_devices_dict):
            # create existing neighbor dict with hostname and management_ip:
            new_neighbor_ip_list.append(neighbors['management_ip'])

    # get neighbors from the new discovered neighbors:
    for mgmt_ip in new_neighbor_ip_list:
        print(f"getting neighbors of the discovered neighbor: {mgmt_ip}")
        temp_result[mgmt_ip] = get_lldp_neighbor(mgmt_ip, imc_username, imc_password)
        print(f"got neighbors of the discovered neighbor: {mgmt_ip}")
        print(100 * "-")

    remove_unwanted_neighbors(temp_result, imc_devices_dict, exclude_device_list)

    return temp_result


def build_interface_list_for_config(
        device_neighbors_dict: dict, root_device_ip_address: str, imc_devices_dict):
    # build local_interface list:
    local_interfaces = defaultdict(dict)
    root_neighbors = list()
    result_list = defaultdict(list)

    for neighbor, neighbor_list in device_neighbors_dict.items():
        # print(f"neighbor: {neighbor}")
        for data in neighbor_list:
            # print(f"management_ip: {data['management_ip']}")
            # print(f"local_interface: {data['local_interface']}")
            # add only valid IMC devices:
            # if check_device_if_imc_device(data['management_ip'], imc_devices_dict):
            #     local_interfaces[neighbor].update({data['management_ip']: data['local_interface']})
            if data['management_ip'] == root_device_ip_address:
                device_neighbors_dict[neighbor].append({"is_root_neighbor": True})
            else:
                device_neighbors_dict[neighbor].append({"is_root_neighbor": False})

    # print(local_interfaces)

    # remove the root neighbor list from local_interfaces:
    local_interfaces.pop(root_device_ip_address)

    """        
    # create list with final interface IDs:
    for mgmt_ip, neighbors in local_interfaces.items():
        if neighbors['is_root_neighbor']:
            result_list[mgmt_ip].append()
    
    
    add "device_link_aggr_members" as variable
    
    # build dhcp snooping bridge-aggregation interface dict:
    dhcp_snooping_config = dict()
    for interface in device_link_aggr_members:
        if interface['member_interface'] in local_interface_list:
            # print(f"LOCAL INTERFACE: {neighbors['local_interface']}, MEMBER OF: {interface['aggr_interface']}")
            dhcp_snooping_config.update({interface['member_interface']: interface['aggr_interface']})

    # add interfaces without imc_port-channel membership to rootDeviceDhcpSnoopingConfig:
    for interface in local_interface_list:
        if interface not in dhcp_snooping_config:
            dhcp_snooping_config.update({interface: interface})
    

    # remove duplicated values from rootDeviceDhcpSnoopingConfig dict:
    dhcp_snooping_config = remove_duplicated_values_from_dict(dhcp_snooping_config)
    for key, value in dhcp_snooping_config.items():
        result_list.append(value)
    """
    return local_interfaces, root_neighbors


def remove_unwanted_neighbors(device_neighbors_dict: dict, imc_devices_dict, exclude_device_list: list):
    """
    remove the following neighbors from the list:
    - root device(s)
    - device not listed at IMC
    """
    index_to_remove = defaultdict(list)
    for new_neighbor, new_neighbor_members in device_neighbors_dict.items():
        # print(new_neighbor_members)
        for idx, member in enumerate(new_neighbor_members):
            if member['neighbor'] in exclude_device_list or \
                    not check_device_if_imc_device(member['management_ip'], imc_devices_dict):
                # print(f"removing exclude device: {new_neighbor}, index: {idx}")
                index_to_remove[new_neighbor].append(idx)
    # print(index_to_remove)
    for mgmt_ip, idx_list in index_to_remove.items():
        # print(f"mgmt_ip: {mgmt_ip}")
        #
        # sort delete_index list in descending order,
        # due to reindexing after pop():
        #
        for delete_index in sorted(idx_list, reverse=True):
            # print(f"mgmt_ip in for loop: {mgmt_ip}")
            # print(f"delete index: {delete_index}")
            # print(secondGradeDeviceNeighbors)
            # sort delete_index list if there is more then one element to delete
            # needed because of reindexing after pop()
            try:
                device_neighbors_dict[mgmt_ip].pop(delete_index)
            except Exception as e:
                print(e)


def build_neighbor_from_imc_network(ipv4_network_obj: str, imc_devices_dict: dict):
    """
    return the switches/neighbors based on the IPv4Network obj
    """
    # create IPv4Network obj from str: ipv4_network_obj:
    ipv4_network_obj = IPv4Network(ipv4_network_obj)
    neighbor_list = list()
    for ipv4 in imc_devices_dict:
        if ipv4 in ipv4_network_obj:
            neighbor_list.append(ipv4)
    return neighbor_list


def get_non_root_neighbors(
        neighbor_list_from_imc: list, imc_devices_dict, exclude_device_list, root_device_ip: str, imc_username,
        imc_password):
    new_neighbor_ip_list = list()
    temp_result = dict()
    final_result = dict()
    # build IP list with the new neighbors
    # and check if it is a rfc1918 address and not an link_local address:
    for non_root_switches in neighbor_list_from_imc:
        """
        if check_if_ipv4_rfc_1918(str(IPv4Address(non_root_switches))) and \
                check_device_if_imc_device(str(IPv4Address(non_root_switches)), imc_devices_dict):
        """
        # create existing neighbor dict with hostname and management_ip:
        new_neighbor_ip_list.append(str(IPv4Address(non_root_switches)))

    # get neighbors from the new discovered neighbors:
    for mgmt_ip in new_neighbor_ip_list:
        print(f"getting neighbors of the discovered neighbor: {mgmt_ip}")
        temp_result[mgmt_ip] = get_lldp_neighbor(mgmt_ip, imc_username, imc_password)
        # resolve mac address in management_ip field :
        resolve_mac_to_mgmt_ip(temp_result[mgmt_ip], imc_devices_dict)

        print(f"got neighbors of the discovered neighbor: {mgmt_ip}")
        print(100 * "-")

    # remove_unwanted_neighbors(temp_result, imc_devices_dict, exclude_device_list)

    return temp_result


def check_if_root_neighbor(device_neighbors_dict: dict, root_device_ip: str):
    for data in device_neighbors_dict.values():
        if data['management_ip'] == root_device_ip:
            is_root_neighbor = True
            return is_root_neighbor
        else:
            is_root_neighbor = False
            return is_root_neighbor
