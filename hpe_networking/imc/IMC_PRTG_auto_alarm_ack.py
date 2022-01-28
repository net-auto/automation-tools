"""
tool for syncing the acknowledged alarms at PRTG
"""

# Standard library imports
import sys

# Third party imports
import click

# Local application imports
from modules.common_functions import \
    get_imc_keyring_credentials, \
    get_prtg_keyring_credentials
from modules.imc import \
    get_confirmed_alerts_down_hosts
from modules.prtg import \
    get_current_down_ping_sensors, \
    get_single_device_obj, \
    ack_alarm

# functions:

# variables:
http_url = "https://"
imc_url = "<IMC_FQDN>:8443"
api_url = "/imcrs/plat/res/device?start=0&size=1000"
headers = {'Accept': 'application/json'}
prtg_host = '<PRTG_FQDN>'
prtg_port = '443'
prtg_protocol = 'https'


@click.command()
@click.option('--imc-username', help='IMC username')
@click.option('--keyring-entry-imc', help='enter the entry name for IMC from the credentials_imc manager')
@click.option('--keyring-entry-prtg', help='enter the entry name for IMC from the credentials_imc manager')
def main(keyring_entry_imc, imc_username, keyring_entry_prtg):
    # check if imc credentials are proper set at the keystore:
    imc_credentials = get_imc_keyring_credentials(keyring_entry_imc, imc_username)
    # IMC username from get_imc_keyring_credentials() result:
    imc_username = imc_credentials[0]
    # IMC password from get_imc_keyring_credentials() result:
    imc_password = imc_credentials[1]

    # check if prtg credentials are proper set at the keystore:
    prtg_credentials = get_prtg_keyring_credentials(keyring_entry_prtg, imc_username)
    prtg_username = prtg_credentials[0]
    prtg_passhash = prtg_credentials[1]

    # get current real time alerts from IMC:
    print("Getting corresponding Alarms from IMC...")
    down_hosts_imc = get_confirmed_alerts_down_hosts(imc_username, imc_password)
    print("Got the Alarms from IMC!")

    # continue only if we get the corresponding devices from IMC:
    if down_hosts_imc:
        # create IP list from down_hosts_imc:
        imc_down_hosts_ip = dict()
        for switch_ip in down_hosts_imc['alarm']:
            imc_down_hosts_ip.update({switch_ip.get('deviceIp'): switch_ip.get('ackUserName')})

        # get current ping sensors which are down:
        print("Getting corresponding Alarms from PRTG...")
        down_ping_sensors = get_current_down_ping_sensors(prtg_username, prtg_passhash)
        print("Got the Alarms from PRTG!")
        if down_ping_sensors:
            # get the parent device obj from the down_ping_sensors
            # and update each element with the parent IP address from PRTG
            # needed for conditional check later on:
            for affectedId in down_ping_sensors:
                prtg_single_obj = get_single_device_obj(prtg_host, prtg_username, prtg_passhash, affectedId["parentid"])
                temp_parent_sensor_ip = str(prtg_single_obj.host)
                affectedId.update({'sensor_parent_IP_address': temp_parent_sensor_ip})
                if temp_parent_sensor_ip in imc_down_hosts_ip:
                    is_to_acknowledge = True
                    affectedId.update({'ack_sensor': is_to_acknowledge})
                else:
                    is_to_acknowledge = False
                    affectedId.update({'ack_sensor': is_to_acknowledge})

            # loop for acknowledge flag and confirm the alarm:
            for affectedId in down_ping_sensors:
                if affectedId.get('ack_sensor'):
                    print(f'Performing ACK for Host: {affectedId["sensor_parent_IP_address"]}')
                    ack_alarm(prtg_user=prtg_username,
                              prtg_passhash=prtg_passhash,
                              sensor_id=affectedId['objid'],
                              ack_user_name=imc_down_hosts_ip.get(affectedId.get('sensor_parent_IP_address'))
                              )
                else:
                    print("NO ALARM TO ACK AT PRTG")
        else:
            print("NO MATCHING DEVICE FOUND AT PRTG!")
    else:
        print("NOTHING DO TO...")
        sys.exit(0)


if __name__ == '__main__':
    main()
    print("FINISHED")
