"""
### Description ###

Script grabs the running config of the devices from IMC and
checks the compliance against the variable: LOGHOST_DEFAULT_ADDRESS
If a different imc_server/syntax is found, then the corresponding
to undo syntax is created and pushed to the device via IMC

"""
import os
from ipaddress import IPv4Address
from time import sleep

import progressbar
from pyhpeimc.auth import *
from pyhpeimc.plat.groups import *

from modules import imc as api

# variables:
http_url = "http://"
imc_url = "<IMC_FQDN>"
imc_port = "8080"
api_url = "/imcrs/plat/res/device?start=0&size=1000"
api_dev_url = "/imcrs/plat/res/device/"
HEADERS_JSON = {'Accept': 'application/json'}
HEADERS_XML = {'Accept': 'application/xml'}
IMC_USER = os.environ.get('IMC_USER')
IMC_PASS = os.environ.get('imc_pass')
AUTH = IMCAuth(http_url, imc_url, imc_port, IMC_USER, IMC_PASS)
LOGHOST_DEFAULT_ADDRESS = '<SYSLOG_BASELINE_IP_ADDRESS_ENTRY>'

if __name__ == "__main__":
    imcFailedDeviceConnect = list()
    imcDevObjRunningCfg = dict()
    devUndoCmds = dict()
    devCmdResult = dict()

    # get all current IMC device:
    allImcDevices = api.getImcDevices(IMC_USER, IMC_PASS)

    # create IMCDev objects with running config from allImcDevice call:
    print("GETTING RUNNING CONFIG OF THE DEVICES FROM IMC:")
    with progressbar.ProgressBar(max_value=len(allImcDevices)) as bar:
        for idx, ipHostnameDevId in enumerate(allImcDevices.items(), start=1):
            # get the running config from imc
            # if a API connection fail occurs, append the device IP to the imcFailedDeviceConnect list()
            tempRunning = api.get_imc_dev_run_cfg(str(ipHostnameDevId[1][1]), IMC_USER, IMC_PASS)
            if tempRunning != 'FAILED':
                imcDevObjRunningCfg[str(ipHostnameDevId[0])] = tempRunning
                bar.update(idx)
            else:
                imcFailedDeviceConnect.append(ipHostnameDevId[0])
                bar.update(idx)
            sleep(0.10)  # sleep for 10ms -> rate limiting

    with open('imcLoghostFailedDeviceConnect.log', 'w') as f:
        for device in imcFailedDeviceConnect:
            f.write(str(IPv4Address(device)) + "\n")

    # print(imcDevObjRunningCfg["172.16.120.115"])
    for ip, runCfg in imcDevObjRunningCfg.items():
        undoCmds = api.createLoghostUndoConfig(runCfg, LOGHOST_DEFAULT_ADDRESS)
        if undoCmds:
            finalLoghostCfg = api.createNewLoghostConfig(undoCmds)
            devUndoCmds[ip] = finalLoghostCfg

    with open('loghostReconfiguredDevices.json', 'w', encoding='utf-8') as f:
        json.dump(devUndoCmds, f, ensure_ascii=False, indent=4)

    print("SENDING PARAMETER TO THE AFFECTED DEVICE:")

    with progressbar.ProgressBar(max_value=len(devUndoCmds)) as bar:
        for idx, affectedIpFinalLoghostCfg in enumerate(devUndoCmds.items(), start=1):
            devCmdResult[affectedIpFinalLoghostCfg[0]] = \
                api.sent_cli_cmd((affectedIpFinalLoghostCfg[0], affectedIpFinalLoghostCfg[1], AUTH.creds, AUTH.url))
            bar.update(idx)

    with open('loghostFinalResults.json', 'w', encoding='utf-8') as f:
        json.dump(devCmdResult, f, ensure_ascii=False, indent=4)

    print(20 * "-" + "FINISHED" + 20 * "-")
