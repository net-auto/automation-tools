"""
WLAN access point hostname renaming script

"""
import click

from modules import ruckus
from modules.common_functions import get_imc_keyring_credentials

# custom variables:
affected_ap_zone_name = "<INSERT_GROUP_NAME"  # example: "AP_GROUP_LAB"
host = "<WLC_FQDN>"


@click.command()
@click.option('--smartzone-username', help='Smart Zone Username')
@click.option('--keyring-entry-smartzone', help='enter the entry name for SmartZone from the credentials_imc manager')
def main(keyring_entry_smartzone, smartzone_username):
    # check if imc credentials are proper set at the keystore:
    credentials = get_imc_keyring_credentials(keyring_entry_smartzone, smartzone_username)
    # IMC username from get_imc_keyring_credentials() result:
    username = credentials[0]
    # IMC password from get_imc_keyring_credentials() result:
    password = credentials[1]

    sz_user = f"{username}@nps"
    sz_password = password
    token = ruckus.get_token(sz_user, sz_password)
    ap_list = ruckus.retrieve_specific_ap_list("0b66db02-ed14-4379-8ddd-066be5b670c3", token)
    print(ap_list)
    new_hostnames = ruckus.create_new_ap_hostname('DE', ap_list, "172.16.156.0")
    print(new_hostnames)
    ruckus.rename_ap(new_hostnames, token)


if __name__ == "__main__":
    main()
