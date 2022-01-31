# -*- coding: utf-8 -*-
"""On-Box Module for IRF configuration based on the autoconfiguration of the comware OS.

for member ID: 1 there is also a baseline config applied. This baseline config is based on
the IMC auto deployment requirements

That means, that the device/switch can be added to the ADP directly for the 2nd stage


"""
# import
import sys

import comware

# variables:
tftp_server = "<TFTP_SERVER_IP"
ipe_file = "5130EI-CMW710-R3506P06.ipe"
sw_version = "R3506P06"
irf_file = "irf_members_mapping.txt"
"""
example content of the irf_members_mapping.txt file:
MEMBER_ID:SERIAL:MGMT_VLAN_ID -> needed for member 1!
1:CN69GQ00G7:100 
2:CN69GQ00G8
3:CN69GQ00G9
"""
irf_prio_numbers = {
    "1": "32",
    "2": "31",
    "3": "30",
    "4": "29",
    "5": "28",
    "6": "27",
    "7": "26",
    "8": "25",
    "9": "24"
}


# functions:

def set_base_config(mgmt_vlan, startup_file):
    """
    MGMT SVI will be set to DHCP
    Args:
        startup_file:
        mgmt_vlan: MGMT VLAN

    Returns:

    Todo:
    - implement the static MGMT IP config at the MGMT VLAN (source data: 1:DPPMWWB76:100:192.168.100.1)
    - set the interface: gi1/0/1 or te1/0/1 as a trunk for the initial staging process
    -> get the first interface by index 1: more ifindex.dat | include " 1>"
    Result:

    5130:
    more ifindex.dat | include " 1>"
    <GigabitEthernet1/0/1 1>

    or 49:
    more ifindex.dat | include " 49>"
    <Ten-GigabitEthernet1/0/49 49>


    5940:
    more ifindex.dat | include " 1>"
    <Ten-GigabitEthernet1/0/1 1>

    or 49:
    more ifindex.dat | include " 49>"
    <HundredGigE1/0/49 49>

    """
    print("WRITING BASE CONFIG FOR MEMBER ID: 1 \n"
          "WITH MGMT VLAN: {mgmt_vlan} \n".format(mgmt_vlan=mgmt_vlan))
    print(50 * "-")

    # set the irf domain and switch priority:
    # startup_file = open('flash:/startup.cfg', 'w')
    startup_file.write("\nsysname ZTP_Initial_Config" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nvlan " + mgmt_vlan + "\n")
    startup_file.write("\nname MGMT_LAN" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\ninterface Vlan-interface" + mgmt_vlan + "\n")
    startup_file.write("\nip address dhcp-alloc" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\ntelnet server enable" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nstp global enable" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nsnmp-agent" + "\n")
    startup_file.write("\nsnmp-agent community read read" + "\n")
    startup_file.write("\nsnmp-agent community write write" + "\n")
    startup_file.write("\nsnmp-agent sys-info version all" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nline aux 0" + "\n")
    startup_file.write("\nuser-role network-admin" + "\n")
    startup_file.write("\nscreen-length 69" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nline vty 0 63" + "\n")
    startup_file.write("\nauthentication-mode scheme" + "\n")
    startup_file.write("\nuser-role network-admin" + "\n")
    startup_file.write("\nuser-role network-operator" + "\n")
    startup_file.write("\nscreen-length 0" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nlocal-user admin class manage" + "\n")
    startup_file.write("\npassword simple admin" + "\n")

    startup_file.write("\nservice-type telnet" + "\n")
    startup_file.write("\nauthorization-attribute user-role level-15" + "\n")
    startup_file.write("\nauthorization-attribute user-role network-admin" + "\n")
    startup_file.write("\nauthorization-attribute user-role network-operator" + "\n")
    startup_file.write("\n#" + "\n")

    # get if_index 1 and configure this as staging trunk interfaces:
    interface_name = get_uplink_by_ifindex("1")
    configure_staging_trunk_intf(interface_name, startup_file)

    # close startup file and set the startup config to the file: startup.cfg
    # startup_file.close()


def create_member_data(irf_members_file_object):
    """
    return a dict with key: serial number, value: member ID
    and if the member should be configured with ID "1", then also the MGMT VLAN ID

    """
    # create members dict:
    irf_members = {}
    for entry in irf_members_file_object.readlines():
        print("MEMBERS ENTRY: {entry}".format(entry=entry))
        split_result = entry.strip().split(":")
        # member_id, sn = entry.strip().split(":")
        if split_result[0] == "1":
            # Example: MEMBERS ENTRY: 1:DPPMWWB76:100
            if len(split_result) == 3:
                irf_members.update({split_result[1].strip(): [split_result[0].strip(), split_result[2].strip()]})
            else:
                print("PLEASE CHECK IF YOU PROVIDED THE MGMT VLAN ID FOR MEMBER 1")
                print("HINT: MEMBER_ID:SERIAL:MGMT_VLAN_ID \n")
                sys.exit("QUITING CONFIGURATION...")
        else:
            irf_members.update({split_result[1].strip(): split_result[0].strip()})
    return irf_members


def get_serial_number_cli():
    """ execute the "show device manuinfo" and extracts the serial number from it

    :return: serial number from the current switch

    """

    # get current device serial number (tested)
    get_dev_sn = comware.CLI('dis device manuinfo | in DEVICE_SERIAL_NUMBER', False).get_output()
    dev_sn = ''
    for line in get_dev_sn:
        if 'DEVICE_SERIAL_NUMBER' in line and 'manuinfo' not in line:
            # split_result = line.splitlines(':')
            dev_sn = line.split(':')[1]  # output example: ['DEVICE_SERIAL_NUMBER', 'DPPMWWB76'] -> only index 1 needed
            break  # because the cli output has redundant output. Only needed once.
    return dev_sn.strip()  # remove any whitespaces


def set_irf_config(irf_member_data, irf_priority_data, startup_file):
    switch_serial_number = get_serial_number_cli()
    print("SWITCH OWN SERIAL NUMBER: {switch_serial_number}".format(switch_serial_number=switch_serial_number))
    print(50 * "-")

    # get the defined member id from file and set the predefined prio:
    if irf_member_data[switch_serial_number][0] == "1":
        member_id = irf_member_data[switch_serial_number][0]
        get_default_priority = irf_priority_data[member_id]
    else:
        member_id = irf_member_data[switch_serial_number]
        get_default_priority = irf_priority_data[member_id]

    # renumbering of the other switches to the new member ID
    # except the switch with member ID: 1 already configured
    current_id_configured = get_current_member_id()
    if current_id_configured != member_id:
        comware.CLI("system ; irf member " + current_id_configured + " renumber " + member_id)
        print("CURRENT MEMBER ID DOES NOT MATCH THE PREDEFINED ONE")
        print("RENUMBERING BASED ON THE CONFIG FILE")
        print("WILL BE CONFIGURED AS FOLLOWS:")
        print("MEMBER ID: {memberId}".format(memberId=member_id))
    elif current_id_configured == "1" and member_id != "1":
        comware.CLI("system ; irf member 1" + " renumber " + member_id)
        print("PERFORMING RENUMBERING TO: {memberId}".format(memberId=member_id))
    elif current_id_configured == member_id:
        print("NOTHING TO CHANGE REGARDING THE MEMBER ID")
        print("ALREADY MEETS THE PREDEFINED ONE")
        print("INFO: predefined member ID: {memberId}".format(memberId=member_id))

    # set the base config for member 1:
    if member_id == "1":
        mgmt_vlan = irf_member_data[switch_serial_number][1]
        set_base_config(mgmt_vlan, startup_file=startup_file)

    print("FOLLOWING MEMBER ID WILL BE USED/CONFIGURED: {memberId}".format(memberId=member_id))
    print("FOLLOWING MEMBER PRIORITY WILL BE USED/CONFIGURED: {set_prio}".format(set_prio=get_default_priority))

    # set the irf domain and switch priority:
    # startup_file = open('flash:/startup.cfg', 'w')
    startup_file.write("\nirf domain 10" + '\n')
    startup_file.write("\nirf member " + member_id + " priority " + get_default_priority + '\n')

    # get IRF interfaces based on the platform:
    irf_port_1, irf_port_2 = get_current_platform_irf_ports(member_id)

    # configure the irf interfaces:
    startup_file.write("\nirf-port " + member_id + "/1")
    # startup_file.write("\nport group interface Ten-GigabitEthernet" + member_id + irf_port_1 + '\n')
    startup_file.write("\nport group interface " + irf_port_1 + '\n')

    startup_file.write("\nirf-port " + member_id + "/2")
    # startup_file.write("\nport group interface Ten-GigabitEthernet" + member_id + irf_port_2 + '\n')
    startup_file.write("\nport group interface " + irf_port_2 + '\n')

    # set IRF interface description:
    startup_file.write("\ninterface " + irf_port_1 + '\n')
    startup_file.write("\ndescription IRF" + '\n')

    startup_file.write("\ninterface " + irf_port_2 + '\n')
    startup_file.write("\ndescription IRF" + '\n')

    # close startup file and set the startup config to the file: startup.cfg
    # startup_file.close()
    # comware.CLI("startup saved-configuration startup.cfg")


def get_current_member_id():
    """

    Return:
        current configured ID as str()
    """
    irf_output = comware.CLI('dis cu co | in "irf member"', False).get_output()
    if len(irf_output) > 1:
        cmd_output = irf_output[1].strip()
        current_id_configured = cmd_output.split(" ")[2]
        return current_id_configured


def get_current_platform_irf_ports(member_id):
    """ execute the "show device manuinfo" and extracts the platform ID from it

    Note:
     To add support for another model, just get the "display device manuinfo" output
     and based on that, append the following example to the end of the if/else loop

    Example::

         elif '<MODEL_NUMBER>' in line:  # <MODEL_DESCRIPTION>
            irf_port_1 = 'Ten-GigabitEthernet' + member_id + '/0/<FIRST_IRF_PORT>'
            irf_port_2 = 'Ten-GigabitEthernet' + member_id + '/0/<SECOND_IRF_PORT>'
            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2

    Returns:

    :param member_id: defined member ID for the switch
    :return: IRF ports / interfaces based on the switch platform

    """

    # get current device serial number (tested)
    get_dev_platform = comware.CLI('dis device manuinfo | in DEVICE_NAME', False).get_output()
    print("SWITCH PLATFORM:\n {get_dev_platform}".format(get_dev_platform=get_dev_platform))
    print(50 * "-")
    irf_port_1 = ''
    irf_port_2 = ''
    for line in get_dev_platform:
        if 'JG937A' in line or 'Simware' in line:  # 5130-48G-PoE+-4SFP+ (370W) and for Lab SIM (H3C)
            irf_port_1 = 'Ten-GigabitEthernet' + member_id + '/0/51'
            irf_port_2 = 'Ten-GigabitEthernet' + member_id + '/0/52'
            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JG896A' in line:  # FF 5700-40XG-2QSFP+
            irf_port_1 = 'FortyGigE' + member_id + '/0/41'
            irf_port_2 = 'FortyGigE' + member_id + '/0/42'
            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JH390A' in line:  # FlexFabric 5940 48SFP+ 6QSFP28
            irf_port_1 = 'FortyGigE' + member_id + '/0/49'
            irf_port_2 = 'FortyGigE' + member_id + '/0/50'
            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JG940A' in line:  # 5130-24G-PoE+-2SFP+-2XGT (370W) EI
            irf_port_1 = 'Ten-GigabitEthernet' + member_id + '/0/27'
            irf_port_2 = 'Ten-GigabitEthernet' + member_id + '/0/28'
            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2


def configure_staging_trunk_intf(if_name, startup_file):
    """

    :param if_name: corresponding interfaces of the index ID as str()
    :param startup_file: startup_file reference
    :return: None
    """
    staging_interface = "\ninterface {if_name} + \n".format(if_name=if_name)
    startup_file.write(staging_interface)
    startup_file.write("\ndescription TEMP_STAGING_TRUNK_INTERFACE" + "\n")
    startup_file.write("\nport link-type trunk" + "\n")
    startup_file.write("\nport trunk permit vlan all" + "\n")
    startup_file.write("\n#" + "\n")


def get_uplink_by_ifindex(if_index):
    """
    based on the comware CLI output from: more ifindex.dat | include " 1>"
    Args:
        if_index: ifindex to use

    Examples:
        ifindex 1 = Gi1/0/1 or Te1/0/1
        ifindex 49 = Gi1/0/49 or Te1/0/49 or Hu1/0/49 or Fo1/0/49

    Returns:

    """
    cli_cmd_if_filter = 'more ifindex.dat | include " {if_index}>"'.format(if_index=if_index)  # leading whitespace is needed!
    if_index_cli_output = comware.CLI(cli_cmd_if_filter, False).get_output()
    # print(if_index_cli_output)
    # example output: ['<SWITCH_HOSTNAME>more ifindex.dat | include " 1>"', '<GigabitEthernet1/0/1 1>']
    if_index_result = if_index_cli_output[1].replace('<', '').split()[0]
    # example output: 'GigabitEthernet1/0/1'
    return if_index_result


def main():
    # get the irfMember.txt file from the TFTP/IMC
    print("GETTING IRF MEMBER MAPPING FILE: {irf_file} FROM TFTP SERVER...".format(irf_file=irf_file))
    comware.Transfer("tftp", tftp_server, irf_file, "flash:/" + irf_file)
    print("GOT IRF MEMBER MAPPING FILE: {irf_file}".format(irf_file=irf_file))
    print(50 * "-")

    # open the irf_members_file -> contains Switch serial and desired member id
    print("OPENING IRF MEMBERS FILE ON LOCAL STORE (flash:/)...")
    irf_members_file = open("flash:/" + irf_file)
    print("DONE")
    print(50 * "-")

    irf_member_data = create_member_data(irf_members_file)
    print("IRF CONFIG DATA: {irf_member_data}".format(irf_member_data=irf_member_data))

    # get serial for checking, if the switch is listed
    serial = get_serial_number_cli()
    if serial in irf_member_data:
        # open/create startup.cfg file:
        startup_file = open('flash:/startup.cfg', 'w')

        print("SETTING UP/CREATING IRF CONFIG...")
        set_irf_config(irf_member_data, irf_prio_numbers, startup_file=startup_file)
        print("DONE")
        print(50 * "-")

        # close and save the new created startup config
        startup_file.close()
        comware.CLI("startup saved-configuration startup.cfg")

        # reboot device without saving running config
        # save force should not be performed or the irf port configuration will be deleted/overwritten
        comware.CLI('reboot force')
    else:
        print(50 * "-")
        print("SWITCH IS NOT LISTED AND WILL NOT BE CONFIGURED...")
        sys.exit()


def get_uplink_by_ifindex(if_index):
    """
    based on the comware CLI output from: more ifindex.dat | include " 1>"
    Args:
        if_index: ifindex to use

    Examples:
        ifindex 1 = Gi1/0/1 or Te1/0/1
        ifindex 49 = Gi1/0/49 or Te1/0/49 or Hu1/0/49 or Fo1/0/49

    Returns:

    """
    if_index_string = " {if_index}".format(if_index=if_index)  # leading whitespace is needed!
    if_index_cli_output = comware.CLI('more ifindex.dat | include' + if_index_string, False).get_output()
    if_index_result = if_index_cli_output.split(' ')[0].replace('<', '')


if __name__ == "__main__":
    main()

"""
Related to software upgrade procedure -> will be implemented later...

# get switch software version (tested)
get_sw_version = comware.CLI('display version | in Software', False).get_output()

test string for get_sw_version 
get_sw_version = "HPE Comware Software, Version 7.1.045, Release 3111P02"

if sw_version in get_sw_version:
    print(f"SOFTWARE VERSION ALREADY COMPLIANT")
    print(f"INSTALLED VERSION:")
    print(get_dev_sn)
else:
    print("NOT COMPLIANT")
    print("DOWNLOADING SOFTWARE FROM TFTP")
    comware.CLI("tftp " + tftp_server + " get " + ipe_file)
    print("SETTING NEW VERSION AS BOOT IMAGE")
    comware.CLI("boot-loader file flash:/" + ipe_file + " all main")
"""
