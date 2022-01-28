from ipaddress import IPv4Address

import PySimpleGUI as sg
import click
import keyring
from pyhpeimc.auth import *

from modules import imc

# variables:
http_url = "https://"
imc_url = "<IMC_FQDN>"
imc_port = "8443"
api_url = "/imcrs/plat/res/device?start=0&size=1000"
api_dev_url = "/imcrs/plat/res/device/"
HEADERS_JSON = {'Accept': 'application/json'}


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
    auth = IMCAuth(h_url=http_url, server=http_url + imc_url, port=imc_port, username=imc_user, password=imc_pass)
    return auth


def showGuiForIpInput():
    # sg.theme('DarkAmber')   # Add a touch of color
    # All the stuff inside your window.
    layout = [[sg.Text('Please type in the Switch IPs:')],
              [sg.Multiline(size=(40, 30))],
              [sg.Submit(), sg.Cancel()]]

    # Create the Window
    window = sg.Window('IPs to be added to IMC', layout, auto_size_text=True)
    # Event Loop to process "events" and get the "values" of the inputs
    event, values = window.read()
    window.close()
    return values[0]


def userInputAsIpv4(guiString):
    # print("DEBUG guiString: ", guiString)
    returnList = list()
    devList = guiString.splitlines()
    print("DEBUG: devlist:", devList)
    for i in devList:
        # returnList.append(IPv4Address(i.strip()))
        try:
            # print("STRIPPED IP:", ip.strip())
            returnList.append(IPv4Address(i.strip()))
        except:
            pass
            # print(f"the value: {i} is not valid and will be ignored")
    return returnList


@click.command()
@click.option('--imc_username', help='IMC username')
@click.option('--keyring_username', help='username name entry at the credentials manager')
def main(imc_username, keyring_username):
    auth_token = imc.imc_keyring_login(imc_username=imc_username, keyring_username=keyring_username)
    user_input_result = showGuiForIpInput()
    # print("DEBUG user_input_result:", user_input_result)
    ip_list = userInputAsIpv4(user_input_result)
    # print("DEBUG ip_list:", ip_list)
    # imcAddDeviceResult = dict()
    for ip in ip_list:
        imc.add_device(ip.compressed, auth_token)


if __name__ == "__main__":
    main()
    print(f"{20 * '-'}FINISHED{20 * '-'}")
    """
    print("RESULT:")
    print(imcAddDeviceResult)
    """
