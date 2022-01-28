"""
describe script/app
"""
from ipaddress import IPv4Network
from pathlib import Path

import click
import keyring
from xlwt import Workbook

from classes import Switch
from modules import imc
from modules.common_functions import get_current_date_filename

# variables:
http_url = "https://"
imc_url = "<IMC_FQDN>:8443"


@click.command()
@click.option('--imc-username', help='IMC username', required=True)
@click.option('--keyring-username', help='username name entry at the credentials manager', required=True)
@click.option('--ipv4-prefix', help='enter the IPv4 prefix you want to be processed', required=True)
def main(keyring_username, imc_username, ipv4_prefix):
    # create IPv4Network object from ipv4_prefix str:
    ipv4_prefix_network = IPv4Network(ipv4_prefix)
    # get credentials from credentials manager:
    credentials = keyring.get_credential(keyring_username, imc_username)
    username = credentials.username
    password = credentials.password

    # get IMC inventory:
    imc_device_inventory = imc.create_switch_inventory(username, password)

    # filter / create new dict() with the specific_prefix network:
    # only getting the mac table from the access switches (5130)
    access_switches = imc.get_access_switches(imc_device_inventory=imc_device_inventory,
                                              specific_prefix=ipv4_prefix_network)

    # get the mac table of each access switch and store it to the "mac_table" attribute:
    for ipv4, switch_data in access_switches.items():
        mac_table = Switch.get_mac_table(username=username,
                                         password=password,
                                         host_ip_address=ipv4.compressed)
        switch_data.mac_table = mac_table

    # resolve / find interfaces where ruckus / commscope APs are connected:
    print('resolving / finding ruckus APs...')
    Switch.resolve_ruckus_mac_oid(access_switches)
    print('DONE')

    # prepare the data export -> excel file
    wb = Workbook()
    # add_sheet is used to create sheet.
    sheet1 = wb.add_sheet('Sheet 1', cell_overwrite_ok=True)
    for idx, switch_data in enumerate(access_switches.items()):
        # print(idx, switch_data)
        sheet1.write(0, idx, switch_data[1].ip_address.compressed)
        for int_idx, ruckus_interface in enumerate(switch_data[1].ruckus_interfaces):
            # print('int_idx: ', int_idx, 'ruckus_interface: ', ruckus_interface)
            sheet1.write(int_idx + 1, idx, ruckus_interface)

    # check if reports folder in the current directory exists. If not, create the folder:
    reports_folder_path = Path('reports/')
    if not Path.exists(reports_folder_path):
        Path.mkdir(reports_folder_path)
    ipv4_prefix_filename = ipv4_prefix_network.network_address.compressed.replace('.', '-')
    wb.save(f"reports/{get_current_date_filename()}_"
            f"{ipv4_prefix_filename}_ruckus_ap_attached_interfaces.xls")


if __name__ == "__main__":
    main()
    print("--- FINISHED ---")
