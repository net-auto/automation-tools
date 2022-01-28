# imports:
import csv
import json
import os
from ipaddress import IPv4Address
from time import sleep

import PySimpleGUI as SimpleGui

from modules import imc

# variables:
imcUsername = os.environ.get('IMC_USER')
imcPassword = os.environ.get('imc_pass')
csv_data = SimpleGui.popup_get_file('CSV file to open')
csv_filename = os.path.basename(csv_data).split(".")[0]
baseUrl = "<IMC_FQDN>"
logfile = f"{csv_filename}_STP_CONFIG_RESULTS.json"

# functions:


# main:
if __name__ == "__main__":
    resultDict = dict()
    print(100 * "-")
    print(f"Using file located at: {csv_data}")
    print(100 * "-")
    print("Getting devices from IMC...")
    imcDevices = imc.get_imc_devices(imcUsername, imcPassword)
    print("Got devices from IMC")
    print(100 * "-")
    # configuration section:
    for row in csv.DictReader(open(csv_data), dialect='excel', delimiter=';'):
        imcDeviceId = imcDevices[IPv4Address(row["host_ip"].strip())][1]
        imcHostname = imcDevices[IPv4Address(row["host_ip"].strip())][0]
        if row["enable_rstp"] == "x":
            print(f'Enabling RSTP for switch: {imcHostname}')
            responseStpConfigRstp = imc.set_stp_config_rstp(baseUrl, imcDeviceId, imcUsername, imcPassword)
            print(f'Enabling RSTP for switch: {imcHostname} done')
            print(100 * "-")
            print("Waiting 60 seconds...")
            sleep(60)  # wait 60 seconds before proceeding
        if row["root_bridge"] == "x":
            print(f'Setting switch: {imcHostname} as root bridge')
            responseStpRstpRootBridge = imc.set_stp_rstp_root_bridge(baseUrl, imcDeviceId, imcUsername, imcPassword)
            print(f'Switch: {imcHostname} set as root bridge')
        if row["enable_dot1t"] == "x":
            print(f'Enabling dot1t extension for switch: {imcHostname}')
            responseStpRstpRootBridge = imc.set_stp_rstp_dot1t_extension(baseUrl, imcDeviceId, imcUsername, imcPassword)
            print(f'dot1t extension for switch: {imcHostname} enabled')

    # verification section:
    for row in csv.DictReader(open(csv_data), dialect='excel', delimiter=';'):
        imcDeviceId = imcDevices[IPv4Address(row["host_ip"].strip())][1]
        switchHostname = imcDevices[IPv4Address(row["host_ip"].strip())][0]
        print(f'verifying config for switch: {switchHostname}')
        responseVerifyStpConfig = \
            api.verifyStpConfig(baseUrl,
                                imcDeviceId,
                                imcUsername,
                                imcPassword,
                                row["enable_rstp"],
                                row["enable_dot1t"],
                                row["enable_dot1t"]
                                )
        resultDict.update({switchHostname: responseVerifyStpConfig})
        print(f'config for switch: {switchHostname} verified')

    print(f"writing logfile: {logfile} ")
    # create logfile:
    resultDictJson = json.dumps(resultDict, indent=4)
    with open(logfile, "w") as outfile:
        outfile.write(resultDictJson)
    print(f"logfile: {logfile} has been written")
    print(100 * "-")
    print(20 * "-" + "FINISHED" + 20 * "-")
