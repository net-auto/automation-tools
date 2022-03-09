# -*- coding: utf-8 -*-
"""On-Box Module for IRF configuration based on the autoconfiguration of the comware OS.

for member ID: 1 there is also a baseline config applied. This baseline config is based on
the IMC auto deployment requirements

That means, that the device/switch can be added to the ADP directly for the 2nd stage

example content of the irf_members_mapping.txt file:
MEMBER_ID:SERIAL:MGMT_VLAN_ID -> needed for member 1!
1:<SWITCH_SERIAL_NUMBER>:<MGMT_VLAN_ID>



if the switch needs to be updated, set the following parameters to fit your needs:
- ftp_server = "<FTP_SERVER_IP>"
- ftp_user = "<FTP_USERNAME>"
- ftp_pass = "<FTP_PASSWORD>"
- access_switch_ipe_file = "5130EI-CMW710-R3506P06.ipe"
- access_switch_ipe_file_md5 = "824C0C93835253B26E81A50130318EF2"
- access_switch_sw_release = "3506P06"
- access_switch_sw_check = True to check the software version and perform the update if necessary


"""
import re
# import
import sys

import comware

# variables:
tftp_server = "<TFTP_SERVER_IP>"
ftp_server = "<FTP_SERVER_IP>"
ftp_user = "<FTP_USERNAME>"
ftp_pass = "<FTP_PASSWORD>"
access_switch_ipe_file = "5130EI-CMW710-R3506P06.ipe"
access_switch_ipe_file_md5 = "824C0C93835253B26E81A50130318EF2"
access_switch_sw_release = "3506P06"
access_switch_sw_check = True
irf_file = "irf_members_mapping.txt"
"""

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

    Result:

    5130:
    <SWITCH_HOSTNAME>more ifindex.dat | include " 1>"
    <GigabitEthernet1/0/1 1>
    <SWITCH_HOSTNAME>
    or 49:
    <SWITCH_HOSTNAME>more ifindex.dat | include " 49>"
    <Ten-GigabitEthernet1/0/49 49>
    <SWITCH_HOSTNAME>

    5940:
    <SWITCH_HOSTNAME>more ifindex.dat | include " 1>"
    <Ten-GigabitEthernet1/0/1 1>
    <SWITCH_HOSTNAME>
    or 49:
    <SWITCH_HOSTNAME>more ifindex.dat | include " 49>"
    <HundredGigE1/0/49 49>
    <SWITCH_HOSTNAME>



    """
    print("WRITING BASE CONFIG FOR MEMBER ID: 1 \n"
          "WITH MGMT VLAN: {mgmt_vlan}".format(mgmt_vlan=mgmt_vlan))
    # print("AND MGMT IP: {mgmt_ip} \n".format(mgmt_ip=mgmt_ip))
    print(50 * "-")

    # set the irf domain and switch priority:
    # startup_file = open('flash:/startup.cfg', 'w')
    startup_file.write("\nsysname ZTP_Initial_Config" + "\n")
    startup_file.write("\n#" + "\n")

    """
    # create SSH key (RSA/1048) and enable SSH (with comware module,
    # -> only default 1048 bit (non fips mode) is possible
    
    Disabled due to issues generating a new key at day 1 -> looks like the key files are locked
    do not have the right permissions.
    
    create_ssh_key()
    startup_file.write("\nssh server enable" + "\n")
    startup_file.write("\n#" + "\n")

    # enable netconf over SSH:
    startup_file.write("\nnetconf ssh server enable" + "\n")
    startup_file.write("\n#" + "\n")
    """

    startup_file.write("\ntelnet server enable" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nstp global enable" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\nsnmp-agent" + "\n")
    startup_file.write("\nsnmp-agent community read iMCread" + "\n")
    startup_file.write("\nsnmp-agent community write iMCwrite" + "\n")
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
    startup_file.write("\nservice-type telnet ssh" + "\n")
    startup_file.write("\nauthorization-attribute user-role level-15" + "\n")
    startup_file.write("\nauthorization-attribute user-role network-admin" + "\n")
    startup_file.write("\nauthorization-attribute user-role network-operator" + "\n")
    startup_file.write("\n#" + "\n")

    # new version of day 1 mgmt interface config:
    mgmt_oob_interface = "M-GigabitEthernet0/0/0"
    # TODO: configure the edge_trunk_interface based on the member-id
    #       and not fixed. Example: {member-id}/0/1
    mgmt_edge_trunk_interface = "GigabitEthernet1/0/1"
    configure_day_1_mgmt_intf(startup_file=startup_file,
                              mgmt_intf=mgmt_oob_interface,
                              edge_interface=mgmt_edge_trunk_interface,
                              mgmt_vlan=mgmt_vlan)
    """
    # get interface by if_index and configure this as staging trunk interfaces:
    interface_name = get_uplink_by_ifindex("1611")  # 1611 = M-GigabitEthernet0/0/0
    if interface_name == 'M-GigabitEthernet0/0/0':
        configure_oob_ip_intf(if_name=interface_name,
                              startup_file=startup_file)
    else:
        configure_staging_trunk_intf(if_name=interface_name,
                                     mgmt_vlan=mgmt_vlan,
                                     startup_file=startup_file)
    """
    # close startup file and set the startup config to the file: startup.cfg
    # startup_file.close()


def configure_staging_trunk_intf(if_name, mgmt_vlan, startup_file):
    """

    :param mgmt_vlan:
    :param if_name: corresponding interfaces of the index ID as str()
    :param startup_file: startup_file reference
    :return: None
    """
    print("CONFIGURING INTERFACE: {if_name} AS DAY 1 MGMT INTERFACE".format(if_name=if_name))
    startup_file.write("\nvlan " + mgmt_vlan + "\n")
    startup_file.write("\nname MGMT_LAN" + "\n")
    startup_file.write("\n#" + "\n")

    startup_file.write("\ninterface Vlan-interface" + mgmt_vlan + "\n")
    startup_file.write("\nip address dhcp-alloc\n")
    startup_file.write("\n#" + "\n")

    staging_interface = "\ninterface {if_name} \n".format(if_name=if_name)
    startup_file.write(staging_interface)
    startup_file.write("\ndescription TEMP_STAGING_TRUNK_INTERFACE" + "\n")
    startup_file.write("\nport link-type trunk" + "\n")
    startup_file.write("\nport trunk permit vlan all" + "\n")
    startup_file.write("\nport trunk pvid vlan " + mgmt_vlan + "\n")
    startup_file.write("\n#" + "\n")


def configure_oob_ip_intf(if_name, startup_file):
    """
    configure the OOB interfaces with vpn instance: "mgmt" -> needed if in-band mgmt interfaces
    overlaps with the OOB interface (will be removed at day 2)

    :param if_name: corresponding interfaces of the index ID as str()
    :param startup_file: startup_file reference
    :return: None
    """
    print("CONFIGURING INTERFACE: {if_name} AS DAY 1 MGMT INTERFACE".format(if_name=if_name))
    startup_file.write("\nip vpn-instance mgmt\n")
    startup_file.write("\ndescription REMOVE_AFTER_DAY_1\n")
    startup_file.write("\n#" + "\n")

    staging_interface = "\ninterface {if_name} \n".format(if_name=if_name)
    startup_file.write(staging_interface)
    startup_file.write("\nip binding vpn-instance mgmt\n")
    startup_file.write("\nip address dhcp-alloc\n")
    startup_file.write("\n#" + "\n")


def configure_day_1_mgmt_intf(startup_file, mgmt_intf, edge_interface, mgmt_vlan):
    """
    get the DEVICE_NAME and use the M-GigabitEthernet0/0/0 if it exists
    else use the GigabitEthernet1/0/1 for the other platforms (access switches = 5130)

    :param mgmt_vlan: management VLAN ID as str(), Example: "7"
    :param edge_interface: edge interface as str(), Example: "GigabitEthernet1/0/1"
    :param mgmt_intf: management interface as str(), Example: "M-GigabitEthernet0/0/0"
    :param startup_file: startup_file reference
    :return:
    """
    get_dev_platform = comware.CLI('dis device manuinfo | in DEVICE_NAME', False).get_output()
    if get_dev_platform:
        model_data = get_dev_platform[1]  # includes first data field which contains the model ID
        # 5130-48G-PoE+-4SFP+ (370W) and for Lab SIM (H3C)
        if re.search('JG937A', model_data) or re.search('Simware', model_data):
            configure_staging_trunk_intf(if_name=edge_interface,
                                         mgmt_vlan=mgmt_vlan,
                                         startup_file=startup_file)
        else:
            configure_oob_ip_intf(if_name=mgmt_intf, startup_file=startup_file)
    else:
        print("COULD NOT CONFIGURE DAY 1 MGMT INTERFACE!\n")
        print("CHECK comware.CLI() syntax/CMD output:\n")
        print(get_dev_platform)


def create_member_data(irf_members_file_object):
    """
    return a dict with key: serial number, value: member ID
    and if the member should be configured with ID "1", then also the MGMT VLAN ID

    """
    # create members dict:
    irf_members = {}
    for entry in irf_members_file_object.readlines():
        # print("MEMBERS ENTRY: {entry}".format(entry=entry))
        split_result = entry.strip().split(":")
        # print("DEBUG SPLIT RESULT:", split_result)
        # member_id, sn = entry.strip().split(":")
        if split_result[0] == "1":
            # Example: MEMBERS ENTRY: 1:DPPMWWB76:100
            if len(split_result) == 3:
                irf_members.update(
                    {split_result[1].strip(): [split_result[0].strip(),  # 1 = SERIAL NUMBER, 0 = IRF MEMBER ID
                                               split_result[2].strip(),  # MGMT VLAN ID
                                               ]
                     }
                )
            else:
                print("PLEASE CHECK IF YOU PROVIDED THE NEEDED PARAMETERS FOR MEMBER 1 ARE SET")
                print("HINT: MEMBER_ID:SERIAL:MGMT_VLAN_ID\n")
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

    # print("DEBUG: IRF_MEMBER_DATA IN set_irf_config():")
    # print(irf_member_data)

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
        # print("DEBUG MGMT_IP IRF_MEMBER_DATA:", irf_member_data)
        # mgmt_ip = irf_member_data[switch_serial_number][2]
        set_base_config(mgmt_vlan=mgmt_vlan, startup_file=startup_file)

    print("FOLLOWING MEMBER ID WILL BE USED/CONFIGURED: {memberId}".format(memberId=member_id))
    print("FOLLOWING MEMBER PRIORITY WILL BE USED/CONFIGURED: {set_prio}".format(set_prio=get_default_priority))

    # set the irf domain and switch priority:
    # startup_file = open('flash:/startup.cfg', 'w')
    startup_file.write("\nirf domain 10" + '\n')
    startup_file.write("\nirf member " + member_id + " priority " + get_default_priority + '\n')

    # get IRF interfaces based on the platform:
    irf_port_1, irf_port_2 = get_current_platform_irf_ports(member_id)

    # configure the irf interfaces:
    for port_1 in irf_port_1:
        startup_file.write("\nirf-port " + member_id + "/1")
        # startup_file.write("\nport group interface Ten-GigabitEthernet" + member_id + irf_port_1 + '\n')
        startup_file.write("\nport group interface " + port_1 + '\n')

        # set IRF interface description:
        startup_file.write("\ninterface " + port_1 + '\n')
        startup_file.write("\ndescription IRF" + '\n')

    for port_2 in irf_port_2:
        startup_file.write("\nirf-port " + member_id + "/2")
        # startup_file.write("\nport group interface Ten-GigabitEthernet" + member_id + irf_port_2 + '\n')
        startup_file.write("\nport group interface " + port_2 + '\n')

        startup_file.write("\ninterface " + port_2 + '\n')
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
    irf_port_1 = list()
    irf_port_2 = list()
    for line in get_dev_platform:
        if 'JG937A' in line or 'Simware' in line:  # 5130-48G-PoE+-4SFP+ (370W) and for Lab SIM (H3C)
            irf_port_1.append('Ten-GigabitEthernet' + member_id + '/0/51')
            irf_port_2.append('Ten-GigabitEthernet' + member_id + '/0/52')

            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JG896A' in line:  # FF 5700-40XG-2QSFP+
            irf_port_1.append('FortyGigE' + member_id + '/0/41')
            irf_port_2.append('FortyGigE' + member_id + '/0/42')

            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JH390A' in line:  # FlexFabric 5940 48SFP+ 6QSFP28
            """
            irf-port 1/1
            port group interface HundredGigE1/0/49
            port group interface HundredGigE1/0/50
            #
            irf-port 1/2
            port group interface HundredGigE1/0/51
            port group interface HundredGigE1/0/52
            #
            """
            irf_port_1.append('HundredGigE' + member_id + '/0/49')
            irf_port_1.append('HundredGigE' + member_id + '/0/50')
            irf_port_2.append('HundredGigE' + member_id + '/0/51')
            irf_port_2.append('HundredGigE' + member_id + '/0/52')

            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JG940A' in line:  # 5130-24G-PoE+-2SFP+-2XGT (370W) EI
            irf_port_1.append('Ten-GigabitEthernet' + member_id + '/0/27')
            irf_port_2.append('Ten-GigabitEthernet' + member_id + '/0/28')
            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2
        elif 'JL587A' in line:  # FlexFabric 5710 24SFP+ 6QSFP+ or 2QSFP28 JL587A
            """
            irf-port 1/1
             port group interface FortyGigE1/0/29
            #
            irf-port 1/2
             port group interface FortyGigE1/0/30
            """
            irf_port_1.append('FortyGigE' + member_id + '/0/29')
            irf_port_2.append('FortyGigE' + member_id + '/0/30')

            print("USING INTERFACES FOR IRF:")
            print("PORT 1: {irf_port_1}".format(irf_port_1=irf_port_1))
            print("PORT 2: {irf_port_2}".format(irf_port_2=irf_port_2))
            return irf_port_1, irf_port_2


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
    cli_cmd_if_filter = 'more ifindex.dat | include " {if_index}>"'.format(
        if_index=if_index)  # leading whitespace is needed!
    if_index_cli_output = comware.CLI(cli_cmd_if_filter, False).get_output()
    # print(if_index_cli_output)
    # example output: ['<SWITCH_HOSTNAME>more ifindex.dat | include " 1>"', '<GigabitEthernet1/0/1 1>']
    if len(if_index_cli_output) > 1:
        # process only if result is included:
        if_index_result = if_index_cli_output[1].replace('<', '').split()[0]
        # example output: 'GigabitEthernet1/0/1'
        return if_index_result
    else:
        # try/anticipate with GigabitEthernet1/0/1:
        print("M-GigabitEthernet0/0/0 missing or ifindex.dat not found! Trying/anticipate with GigabitEthernet1/0/1")
        return 'GigabitEthernet1/0/1'


def create_ssh_key():
    print("creating SSH key ...")
    config = [
        "system-view",
        # destroy any existing local key:
        "public-key local destroy rsa",
        # generate the new local key with RSA and default 1024 bit
        "public-key local create rsa"
    ]
    try:
        comware.CLI(' ;'.join(config), False)
        print("SSH key created")
    except SystemError:
        print("Problem creating SSH ...")
        print("Skipping this step")


def perform_sw_update():
    """
    test string for get_sw_version
    get_sw_version = "HPE Comware Software, Version 7.1.045, Release 3111P02"

    """

    # perform the upgrade:
    # comware.CLI("boot-loader file flash:/s6850-cmw710-boot-a7028.bin all main")
    get_dev_platform = comware.CLI('dis device manuinfo | in DEVICE_NAME', False).get_output()
    for line in get_dev_platform:
        if 'JG937A' in line:  # 5130-48G-PoE+-4SFP+ (370W) and for Lab SIM (H3C)
            if not check_sw_version_compliant(access_switch_sw_release):
                if check_sw_file_already_exists_flash(access_switch_ipe_file):
                    perform_sw_md5_checksum(access_switch_ipe_file)
                    md5_result = perform_sw_md5_checksum(access_switch_ipe_file)
                    if md5_result:
                        print("MD5 checksum of file: {access_switch_ipe_file} "
                              "was successfully checked".format(access_switch_ipe_file=access_switch_ipe_file))
                        bootloader_result = execute_bootloader_file_cli_cmd(access_switch_ipe_file)
                        print("bootloader CLI result:")
                        print(bootloader_result)
                    else:
                        print("CHECKSUM CHECK WAS NOT SUCCESSFUL. SKIPPING SOFTWARE UPDATE ...")
                        break
                else:
                    print("FILE:", access_switch_ipe_file, "not in flash!")
                    print("using FTP server:", ftp_server + " to get the software file ..")
                    get_sw_over_ftp(access_switch_ipe_file)
                    md5_result = perform_sw_md5_checksum(access_switch_ipe_file)
                    if md5_result:
                        print("MD5 checksum of file: {access_switch_ipe_file} "
                              "was successfully checked".format(access_switch_ipe_file=access_switch_ipe_file))
                        bootloader_result = execute_bootloader_file_cli_cmd(access_switch_ipe_file)
                        print("bootloader CLI result:")
                        print(bootloader_result)
                    else:
                        print("CHECKSUM CHECK WAS NOT SUCCESSFUL. SKIPPING SOFTWARE UPDATE ...")
                        break
                break


def get_sw_over_ftp(filename):
    """
    gets the firmware via FTP and performs a MD5 checksum operation

    :return:
    """
    print(
        "GETTING SOFTWARE IMAGE: {ipe_file} FROM FTP SERVER {ftp_server}: ...".format(ipe_file=access_switch_ipe_file,
                                                                                      ftp_server=ftp_server))
    transfer_result = comware.Transfer("ftp",
                                       ftp_server,
                                       filename,
                                       "flash:/" + filename,
                                       user=ftp_user,
                                       password=ftp_pass)
    if not transfer_result.get_error():
        print("FILE SUCCESSFUL TRANSFERRED VIA FTP")
    else:
        print("ERROR OCCURRED DURING FTP TRANSMISSION")
        print("TRANSFER RESULT:")
        print(transfer_result.get_error())


def perform_sw_md5_checksum(filename):
    """
    perform a MD5 checksum routine on the transferred file and return True, if successful
    :return:

    :Example:
    Successful file check result:
    ['<SWITCH>md5sum flash:/5130EI-CMW710-R3506P06.ipe', 'MD5 digest:', '824c0c93835253b26e81a50130318ef2']

    """
    md5_result = comware.CLI('md5sum flash:/' + filename, False).get_output()
    if md5_result:
        if access_switch_ipe_file_md5.lower() == md5_result[2].lower():
            return True
        else:
            return False


def check_sw_version_compliant(version):
    sw_version_result = comware.CLI('display version | in Software', False).get_output()
    # print(sw_version_result)
    if sw_version_result:
        if re.search(version, sw_version_result[1]):
            # print("SOFTWARE VERSION ALREADY COMPLIANT")
            return True
        else:
            return False


def check_sw_file_already_exists_flash(filename):
    try:
        ipe_file_open = open("flash:/" + filename)
        return True
    except IOError:
        return False


def execute_bootloader_file_cli_cmd(filename_ipe):
    boot_loader_result = comware.CLI("boot-loader file flash:/" + filename_ipe + " all main", False).get_output()
    return boot_loader_result


def main():
    # get the irfMember.txt file from the TFTP/IMC
    print("GETTING IRF MEMBER MAPPING FILE: {irf_file} FROM TFTP SERVER...".format(irf_file=irf_file))
    comware.Transfer("tftp", tftp_server, irf_file, "flash:/" + irf_file)
    print("GOT IRF MEMBER MAPPING FILE: {irf_file}".format(irf_file=irf_file))
    print(50 * "-")

    # open the irf_members_file -> contains Switch serial and desired member id
    print("TRY OPENING IRF MEMBERS FILE ON LOCAL STORE (flash:/)...")
    try:
        irf_members_file = open("flash:/" + irf_file)
        print("DONE")
        print(50 * "-")
    except IOError:
        print("FILE:", irf_file, "not in flash!")
        print("USED TFTP server: ", tftp_server)
        print("check if this is the right TFTP server")
        sys.exit("QUITTING AUTO-CONFIGURATION...")

    irf_member_data = create_member_data(irf_members_file)
    # print("IRF CONFIG DATA: {irf_member_data}".format(irf_member_data=irf_member_data))

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

        # software update, if "access_switch_sw_check" flag is set to True:
        if access_switch_sw_check:
            perform_sw_update()

        # reboot device without saving running config
        # save force should not be performed or the irf port configuration will be deleted/overwritten
        comware.CLI('reboot force')
    else:
        print(50 * "-")
        print("SWITCH IS NOT LISTED AND WILL NOT BE CONFIGURED...")
        sys.exit()


if __name__ == "__main__":
    main()
    print("FINISHED")
