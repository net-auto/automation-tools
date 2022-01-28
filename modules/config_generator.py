import csv
import datetime
import logging
import shutil
from ipaddress import IPv4Address
from pathlib import Path

import PySimpleGUI as SimpleGui
import PySimpleGUI as sg
import jinja2
from PySimpleGUI import popup_get_file

from classes.Switch import Switch


def get_last_octet_as_int(ip):
    try:
        start = ip.rindex(".") + 1
        end = len(ip)
        last_octet = int(ip[start:end])
        return last_octet
    except ValueError:
        print('passed IP variable is not a valid IPv4 address')
        print(f'IP variable value is:{ip}')
        pass


def create_logging_instance(log_filename):
    log_filename = f"new_created_switches.log"
    logging.basicConfig(filename=log_filename,
                        format='%(asctime)s %(message)s',
                        filemode='w')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)


def transform_vlan_data(row):
    # the first thing we want to do is remove all fields that start with
    # "vlan_" from the original dictionary.  we only want to keep the
    # fields that do not have a value of "0" as the csv-data uses "0" to
    # indicate a non-used vlan.  The result is a dictionary.

    vlan_fields = {
        field_name: field_value
        for field_name, field_value in list(row.items())
        if field_name.startswith('add_vlan_') and row.pop(field_name)
        if field_value != '0'
    }
    # now that we have that field list, we want to map the "vlan_name_<n>"
    # values to the actual "vlan_id_<n>" values.  we want to create a new
    # entry in the original dictionary called 'vlans' to store this new
    # vlan dictionary.  We also need to handle the case when the vlan name
    # has whitespace; so covert spaces to underscores (_).

    row['vlans'] = {
        vlan_fields[f].replace(' ', '_'): vlan_fields[f.replace('name', 'id')]
        for f in vlan_fields if f.startswith('add_vlan_name')
    }
    return row['vlans']


def load_jinja(filename):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(filename.parent),
        trim_blocks=True, lstrip_blocks=True)
    loaded_template = env.get_template(filename.name)
    return loaded_template


def create_hostname_from_ip(mgmt_ip, country_code):
    """
    example country code: CH, UK
    creates the switch hostname based on the mgmt IP and the country code
    """
    try:
        temp_ip_split = mgmt_ip.split(".")
        hostname = \
            f"SWI{country_code}{temp_ip_split[1].zfill(3)}{temp_ip_split[2].zfill(3)}{temp_ip_split[3].zfill(3)}"
        hostname = hostname.upper()
        return hostname
    except IndexError:
        print('MGMT IP is not a valid IPv4 address')
        print(f'mgmt_ip variable value is:{mgmt_ip}')
        pass


def generate_new_switch_objects(csv_file):
    switch_objects = dict()
    vlan_file_input = popup_get_file("Please select the VLANs file")
    vlan_intf_input = popup_get_file("Please select the VLAN interface file")

    for row in csv.DictReader(open(csv_file), dialect='excel', delimiter=';'):
        new_vlans = transform_vlan_data(row)
        hostname = create_hostname_from_ip(row['ip_address'], row['country_code'])
        subnet_mask = row['subnet_mask']
        ipv4 = IPv4Address(row['ip_address'])
        switch_obj = Switch(ipv4=ipv4)
        switch_obj.hostname = hostname
        switch_obj.subnet_mask = subnet_mask
        switch_obj.vlans = new_vlans
        switch_obj.sys_location = row['sys_location']
        # switch_obj.uplink_intf_id = row['uplink_intf_id']
        switch_obj.uplink_switch_ip = row['uplink_switch_ip']
        switch_obj.default_gw = row['default_gw']
        switch_obj.stack_count = row['stack_count']
        switch_obj.country_code = row['country_code']
        switch_obj.uplink_hostname = \
            create_hostname_from_ip(switch_obj.uplink_switch_ip, switch_obj.country_code)
        switch_obj.uplink_lacp_id = get_last_octet_as_int(switch_obj.uplink_switch_ip)
        switch_obj.mgmt_vlan = row['mgmt_vlan']
        switch_obj.mgmt_vlan_desc = row['mgmt_vlan_desc']
        switch_obj.access_pvid = row['access_vlan_pvid']
        switch_obj.root_bridge = row['root_bridge']
        switch_obj.root_downstream_1 = row['root_downstream_1']
        switch_obj.root_downstream_2 = row['root_downstream_2']
        # switch_obj.single_uplink = row['single_uplink']
        switch_obj.model = row['model']
        switch_obj.available_uplinks = int(row['stack_count']) * 4
        switch_obj.configure_firewall_intf = row['configure_firewall_intf']
        switch_obj.vpn_or_mpls = row['vpn_or_mpls']
        switch_obj.use_vlan_file = row['use_vlan_file']
        switch_obj.migration_link = row['migration_link']
        switch_obj.migration_br_aggr_id = row['migration_br_aggr_id']
        switch_obj.migration_br_aggr_id = row['migration_br_aggr_id']

        # get vlan file if option is set:
        if row['use_vlan_file'] == "x":
            switch_obj.vlan_file_input = vlan_file_input
            switch_obj.vlans_data = create_vlans_data(vlan_file_input)

        # get vlan interface file if option is set:
        if row['use_vlan_intf_file'] == "x":
            switch_obj.vlan_intf_data = create_vlan_interface_data(vlan_intf_input)

        # set available downlinks:
        intf_count = row['model'].split("-")
        if int(intf_count[1].strip()) == 24:  # Example: index 0 = 5940, index 1 = 24
            switch_obj.available_downlinks = 24
        elif int(intf_count[1].strip()) == 48:
            switch_obj.available_downlinks = 48
        # switch_obj.uplink_start_index = 49
        # switch_obj.uplink_end_index = 50
        switch_objects.update({ipv4: switch_obj})
    return switch_objects


def build_root_config_neighbors(switch_objects):
    """

    Args:
        switch_objects: Switch()

    Returns:
    list with the neighbors as Switch() object
    of the root_bridge assigned to the root_bridge Switch().config_neighbors attribute

    """
    # get root bridge index:
    for ipv4, switch_obj in switch_objects.items():
        if switch_obj.root_bridge.lower() == 'x':
            root_bridge_index = switch_obj.ip_address

    switch_objects[root_bridge_index].config_neighbors = list()
    for ipv4, switch_obj in switch_objects.items():
        if switch_obj.uplink_switch_ip == root_bridge_index.compressed:
            switch_objects[root_bridge_index].config_neighbors.append(switch_obj)


def build_uplink_lacp_id(switch_objects: dict):
    """
    build and assign the lacp to the Switch() objects
    Args:
        switch_objects: Switch() dict

    Returns:
    adds the uplink lacp ID to the switch object
    """
    for ipv4, switch_obj in switch_objects.items():
        switch_obj.uplink_lacp_id = get_last_octet_as_int(ipv4.compressed)


def build_uplink_hostname(switch_objects: dict):
    """

    Args:
        switch_objects: Switch() dict

    Returns:

    """
    # get root bridge index:
    for ipv4, switch_obj in switch_objects.items():
        if switch_obj.root_bridge.lower() == 'x':
            root_bridge_index = switch_obj.ip_address

    for ipv4, switch_obj in switch_objects.items():
        if switch_obj.root_bridge.lower() != 'x':
            switch_obj.uplink_hostname = \
                switch_objects[root_bridge_index].hostname


def build_downlink_config_5130(switch_objects):
    for ipv4, switch_obj in switch_objects.items():
        downlink_prefix = 'Ten-GigabitEthernet'
        # build uplink section:
        if switch_obj.uplink_switch_ip != 'o':
            switch_obj.uplink_lacp_cfg = \
                f"interface Bridge-Aggregation {get_last_octet_as_int(switch_obj.uplink_switch_ip)}"
            if int(switch_obj.stack_count) == 1:
                temp_intf_string = \
                    f'interface range Ten-GigabitEthernet1/0/49 to Ten-GigabitEthernet1/0/50'
                switch_obj.uplink_range_cfg = temp_intf_string
            else:
                temp_intf_string = \
                    f'interface range Ten-GigabitEthernet1/0/49 Ten-GigabitEthernet2/0/49'
                switch_obj.uplink_range_cfg = temp_intf_string

        # build downlink section:
        if hasattr(switch_obj, 'config_neighbors'):
            neighbor_cfg = dict()
            for neighbor_ipv4 in switch_obj.config_neighbors:
                temp_neighbor_desc = f'to_{neighbor_ipv4.hostname}'
                idx = neighbor_ipv4.ip_address.compressed
                neighbor_cfg[idx] = dict()
                neighbor_cfg[idx]['desc'] = temp_neighbor_desc
                neighbor_cfg[idx]['lacp_id'] = get_last_octet_as_int(neighbor_ipv4.ip_address.compressed)
                neighbor_cfg[idx]['members'] = []
                # assign downstream interfaces, only if != 'o'
                if neighbor_ipv4.root_downstream_1.strip() != 'o':
                    # remove whitespaces from the input:
                    root_downstream_1 = downlink_prefix + neighbor_ipv4.root_downstream_1.strip()
                    neighbor_cfg[idx]['members'].append(root_downstream_1)
                if neighbor_ipv4.root_downstream_2.strip() != 'o':
                    # remove whitespaces from the input:
                    root_downstream_2 = downlink_prefix + neighbor_ipv4.root_downstream_2.strip()
                    neighbor_cfg[idx]['members'].append(root_downstream_2)
            switch_obj.neighbor_downlink_cfg = neighbor_cfg


def render_config(destination_folder, switch_objects, template_filename, logger_obj=None):
    """

    Args:
        destination_folder: Path()
        switch_objects: Switch()
        template_filename: Path()
        logger_obj:

    Returns:

    """
    template = load_jinja(template_filename)
    for ipv4, switch_obj in switch_objects.items():
        output_filename = f'/{switch_obj.hostname}.txt'
        with open(destination_folder.as_posix() + output_filename, 'w+') as f:
            f.write(template.render(switch_obj=switch_obj,
                                    func_create_hostname=create_hostname_from_ip,
                                    getLastOctectAsInt=get_last_octet_as_int
                                    )
                    )
            if logger_obj:
                logger_obj.info(
                    f"CONFIG CREATED FOR SWITCH: {switch_obj.hostname}"
                )
                logger_obj.info(100 * '-')


def show_selection_gui():
    sg.theme('DarkAmber')
    layout = [
        [sg.Text('Please choose what method you want to use:')],
        [sg.Radio('Migration', group_id="RADIO1", size=(10, 1), key="migration"),
         sg.Radio('New Site/Replacement', group_id="RADIO1", default=True, size=(20, 1), key="new_site")],
        [sg.Text('Please choose which sys_description you want to configure:')],
        [sg.Checkbox('5130 series', default=True, size=(10, 1), key="5130"),
         sg.Checkbox('5940/5710 series', size=(15, 1), key="5940_5710")],
        [sg.Button('Commit')]
    ]
    window = sg.Window('Mode/Option Selection', layout)
    while True:  # The Event Loop
        event, values = window.read()
        print(event, values)
        if event == sg.WIN_CLOSED or event == 'Commit':
            break
    window.close()
    return values


def show_csv_gui():
    layout = [
        [sg.Text('Please choose the corresponding CSV file for the 5130 series switches:')],
        [sg.Input(default_text="Please select the CSV file for new sites"), sg.FileBrowse(key="CSV_5130")],
        [sg.Button('Confirm and close Window'), sg.Button('Cancel')]
    ]
    window = SimpleGui.Window('<NEW SITES> 5130 CSV FILE picker ', layout)
    event, values = window.read()
    window.close()
    return values['CSV_5130']


def show_gui_for_single_device():
    layout = [[SimpleGui.Text('Country Code:'), SimpleGui.InputText(key="country_code", default_text="CH")],
              [SimpleGui.Text('IP Address:'), SimpleGui.InputText(key="new_ip_address")],
              [SimpleGui.Text('Subnetmask:'), SimpleGui.InputText(key="subnet", default_text="255.255.255.0")],
              [SimpleGui.Text('MGMT VLAN ID:'), SimpleGui.InputText(key="mgmt_vlan", default_text="1")],
              [SimpleGui.Text('Client PVID:'), SimpleGui.InputText(key="access_port_pvid", default_text="1")],
              [SimpleGui.Text('Default Gateway:'), SimpleGui.InputText(key="default_gw")],
              [SimpleGui.Text('(SNMP) Location:'), SimpleGui.InputText(key="sys_location")],
              [SimpleGui.Text('Hostname Uplink Switch'),
               SimpleGui.InputText(key="uplink_switch_name", default_text="RENAME_AFTER_INSTALL")],
              [SimpleGui.Text('STP Mode:', pad=(210, 5))],
              [SimpleGui.Radio('RSTP', "RADIO1", default=True, size=(10, 1), key="rstp"),
               SimpleGui.Radio('(Legacy) STP', "RADIO1", size=(20, 1), key="stp"),
               SimpleGui.Checkbox('dot1t extension?', key="dot1t")],
              [SimpleGui.Submit(), SimpleGui.Cancel()]]

    window = SimpleGui.Window('Single (NEW) Device mode', layout, element_justification="right")
    event, values = window.read()
    # window.write_event_value('-THREAD-', '** DONE **')  # put a message into queue for GUI
    window.close()
    print(values)
    return values


def copy_dummy_template_to_dfs(file_source=None, dfs_dir=None):
    """
    copy dummy file to DFS folder
    file existence will be checked and moved to the ARCHIVE folder if needed

    overwrite file_source and dfs_path if needed

    Args:
        dfs_dir: Path()
        file_source: Path()

    Returns:
    None
    """
    # variables:
    now = datetime.datetime.now()
    # format: YYYY_MM_DD
    dt_string = f"{now.year}_{now.month}_{now.day}"
    # set DFS paths:
    dfs_dir = Path("F:/IT/Informatik/Manuals/Network/_Vorlagen/Template_Configuration/")
    dfs_dir_content = list(dfs_dir.iterdir())
    # create filename list from dfs_dir_content:
    dfs_dir_filenames = list()
    for file in dfs_dir_content:
        dfs_dir_filenames.append(file.name)
    dfs_archive = Path("F:/IT/Informatik/Manuals/Network/_Vorlagen/Template_Configuration/ARCHIVE")
    file_source = Path("CONFIG_OUTPUT/SWICH111111111.txt")
    destination_filename = f'5130_2_MEMBERS_ROOT_BRIDGE_VPN_IRF_TEMPLATE.cfg'
    new_filename_path = dfs_dir.as_posix() + '/' + destination_filename
    archive_filename = f'{dt_string}_{destination_filename}'
    archive_path = dfs_archive.as_posix() + '/' + archive_filename
    # check if config file is already in the main directory
    # if the config is there, the file will we moved to the "ARCHIVE" folder
    if destination_filename in dfs_dir_filenames:
        print("FILE FOUND!")
        print("MOVING FILE TO ARCHIVE")
        shutil.move(new_filename_path, archive_path)
    print("COPYING FILE TO DFS SHARE...")
    shutil.copy(file_source, new_filename_path)
    print("COPYING FILE DONE")


def create_vlans_data(csv_path) -> dict:
    """

    Args:
        csv_path: path to the corresponding CSV file

    Returns:
        a dict with vlan_id:vlan_name mapping

    Examples:
        {'2': 'Printers',
         '3': 'CCTV_&_TVs',
         '4': 'Time_clocks',
         '5': 'Voice_IP'}

    """
    vlans_result = dict()
    with open(csv_path, 'r') as f:
        # store/discard the headers in a separate variable,
        # move the reader object to point on the next row
        headers = next(f)
        # print(f"headers: {headers}")
        for line in csv.DictReader(f, delimiter=';', fieldnames=('vlan_id', 'vlan_name')):
            vlans_result.update({line['vlan_id'].strip(): line['vlan_name'].replace(' ', '_').upper().strip()})
    # print(vlans_result)
    return vlans_result


def create_vlan_interface_data(csv_path) -> dict:
    """

    Args:
        csv_path: path to the corresponding CSV file

    Returns:
        a dict with vlan_interface_id: ipaddress, subnet_mask mapping

    Examples:
        {'2': ['10.155.2.254', '255.255.255.0'],
         '3': ['10.155.3.254', '255.255.255.0'],
         '4': ['10.155.4.254', '255.255.255.0'],
         '5': ['10.155.5.254', '255.255.255.0']}

    """
    vlan_interface_result = dict()
    with open(csv_path) as f:
        with open(csv_path, 'r') as f:
            # store/discard the headers in a separate variable,
            # move the reader object to point on the next row
            headers = next(f)
            # print(f"headers: {headers}")
            for line in csv.DictReader(f, delimiter=';', fieldnames=('vlan_interface', 'ip_address', 'subnet_mask')):
                vlan_interface_result.update(
                    {line['vlan_interface'].strip(): [line['ip_address'].strip(), line['subnet_mask'].strip()]}
                )

    return vlan_interface_result
