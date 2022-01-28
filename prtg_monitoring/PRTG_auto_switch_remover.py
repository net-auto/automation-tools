import logging
import os
import sys
from ipaddress import IPv4Address
from pathlib import Path

from modules import common_functions as api
from modules import imc
from modules import prtg

# variables:
http_url = "https://"
imc_url = "<IMC_FQDN"
imc_port = ":8443"
api_url = "/imcrs/plat/res/device?start=0&size=1000"
api_dev_url = "/imcrs/plat/res/device/"
HEADERS_JSON = {'Accept': 'application/json'}
HEADERS_XML = {'Accept': 'application/xml'}
PRTG_HOST = "<PRTG_FQDN>"
PRTG_USER = os.environ.get('PRTG_USER')
PRTG_PASSHASH = os.environ.get('PRTG_PWHASH')
IMC_USERNAME = os.environ.get('IMC_USER')
IMC_PASS = os.environ.get('imc_pass')
mail_receivers = api.check_email_cli_argument(sys.argv)
LOGS_DIR = Path("logs")


def main():
    # instantiate logger obj and check if "logs" directory exists,
    # logs folder will be created if not:
    if not Path.exists(LOGS_DIR):
        Path.mkdir(LOGS_DIR)
    log_filename = "logs/PRTG_auto_switch_remover.log"
    logging.basicConfig(filename=log_filename,
                        format='%(asctime)s %(message)s',
                        filemode='w')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    operator_log_result = \
        imc.get_deleted_device_from_operator_log(IMC_USERNAME, IMC_PASS)
    prtg_objects = \
        prtg.get_prtg_all_objects(prtg_user=PRTG_USER, prtg_passhash=PRTG_PASSHASH)
    prtg_devices = prtg_objects.alldevices
    affected_devices = dict()
    for deleted_device in operator_log_result:
        affected_devices.update(
            {deleted_device: prtg.get_prtg_single_device(IPv4Address(deleted_device), prtg_devices)}
        )
    logger.info(f'# The following IP address / device was delete at IMC'
                f'and has been removed from PRTG:')
    logger.info(100 * '-')
    # delete affected devices without confirmation:
    for ipv4, prtg_object in affected_devices.items():
        print(f'deleting device: {ipv4}')
        prtg.delete_prtg_device(prtg_object)
        print(f'# device: {ipv4} deleted!')
        logger.info(f'### {ipv4} ###')
    logger.info(100 * '-')
    mail_subject = "Report: PRTG Device deletion"
    api.send_mail(
        log_filename, mail_receivers, mail_subject, from_header='PRTG Device Cleaner')


if __name__ == "__main__":
    main()
    print("---FINISHED---")
