"""
### Description ###

Script grabs the running config of the devices from IMC and checks the compliance against the variable: ntp_default_ip
If a different imc_server/syntax is found, then the corresponding undo syntax is created and pushed to the device via IMC

"""
import os
from ipaddress import IPv4Address
from time import sleep

import progressbar
from pyhpeimc.auth import *
from pyhpeimc.plat.groups import *

from modules import imc as api
from modules.common_functions import send_mail

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
NTP_DEFAULT_ADDRESS = '<SET_BASELINE_NTP_IP_ADDRESS>'

if __name__ == "__main__":
    imcFailedDeviceConnect = list()
    imcDevObjRunningCfg = dict()
    devUndoCmds = dict()
    devCmdResult = dict()

    # get all current IMC device:
    allImcDevices = api.get_imc_devices(IMC_USER, IMC_PASS)

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

    with open('imcFailedDeviceConnect.log', 'w') as f:
        for device in imcFailedDeviceConnect:
            f.write(str(IPv4Address(device)) + "\n")

    # print(imcDevObjRunningCfg["172.16.120.115"])

    # TODO: improve config check
    for ip, runCfg in imcDevObjRunningCfg.items():
        undoCmds = api.create_ntp_undo_config(runCfg, NTP_DEFAULT_ADDRESS)
        if undoCmds:
            finalNtpCfg = api.create_new_ntp_config(undoCmds)
            devUndoCmds[ip] = finalNtpCfg

    with open('ntpReconfiguredDevices.json', 'w', encoding='utf-8') as f:
        json.dump(devUndoCmds, f, ensure_ascii=False, indent=4)

    print("SENDING PARAMETER TO THE AFFECTED DEVICE:")

    with progressbar.ProgressBar(max_value=len(devUndoCmds)) as bar:
        for idx, affectedIpFinalNtpCfg in enumerate(devUndoCmds.items(), start=1):
            devCmdResult[affectedIpFinalNtpCfg[0]] = api.sent_cli_cmd(
                (affectedIpFinalNtpCfg[0], affectedIpFinalNtpCfg[1],
                 AUTH.creds, AUTH.url))
            bar.update(idx)

    with open('ntpFinalResults.json', 'w', encoding='utf-8') as f:
        json.dump(devCmdResult, f, ensure_ascii=False, indent=4)

    # 
    # --- section for sendMail ---
    # sending mail only if devCmdResult dict contains values:
    if devCmdResult:
        ipList = list()
        msgString = str()
        # get keys(IPs) from the devCmdResult dict:
        for i in devCmdResult.keys():
            ipList.append(i)
        # create payload for the sending mail:
        msgString = "The following devices was not compliant with the NTP config:" + 2 * "\n" + '\n'.join(ipList)
        # sending mail via function:
        send_mail(msgString, "<INSERT_EMAIL_ADDRESS>rail.com", "NTP Compliance Results")

    print(20 * "-" + "FINISHED" + 20 * "-")
