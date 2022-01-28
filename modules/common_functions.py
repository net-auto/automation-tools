import logging
# Import smtplib for the actual sending function:
import smtplib
import sys
from datetime import datetime
# Import the email modules:
from email.message import EmailMessage
from pathlib import Path

import keyring
from pyhpeimc.plat.groups import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# disable ssl cert validation
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# general functions:

def create_logging_instance(log_filename):
    """
    checks if the subdir: "logs" in the current script folder exists
    if not, the subdirectory will be created and the logfile will be stored there

    Args:
        log_filename: filename of the logfile

    Returns:
    logging() object with INFO loglevel set
    """
    log_path = Path('logs/')
    if not Path.exists(log_path):
        Path.mkdir(log_path)
    log_filename_with_path = log_path / log_filename
    logging.basicConfig(filename=log_filename_with_path.as_posix(),
                        format='%(asctime)s %(message)s',
                        filemode='w')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    return logger, log_filename_with_path


def jDumps(obj):
    # create a formatted string of the Python JSON object
    text = json.dumps(obj, sort_keys=True, indent=4)
    return text


def send_mail(payload, mail_receivers, mail_subject, from_header) -> str:
    """

    Args:
        payload:
        mail_receivers:
        mail_subject:
        from_header:

    Returns:
    sending status as str()
    """
    sender = '<INSERT_EMAIL_ADDRESS>'
    receivers = [mail_receivers]
    # Open the plain text file whose name is in payload for reading.
    with open(payload) as log:
        # Create a text/plain message
        msg = EmailMessage()
        msg.set_content(log.read())

    msg['From'] = f"{from_header} <{sender}>"
    # if mail_receivers has multiple entries, join the values (creates a list):
    msg['To'] = ", ".join(receivers)
    msg['Subject'] = str(mail_subject)
    # print(msg.get_content())
    try:
        smtp_obj = smtplib.SMTP('<INSERT_SMTP_RELAY_SERVER_ADDRESS>')
        smtp_obj.send_message(msg)
        smtp_obj.quit()
        return "Successfully sent email"
    except Exception as e:
        return f'Error: unable to send email". Exception: "{e}"'


def check_email_cli_argument(sys_argv: sys.argv):
    # [0] first argv = script filename
    # [1] second argv = email-id
    if len(sys_argv) != 2:
        sys.exit('Please set the email-id as first cli argument. Needed for the script result report.')
    else:
        return sys_argv[1]


def check_imc_credentials(keyring_entry_imc, imc_username):
    """

    Args:
        keyring_entry_imc:
        imc_username:

    Returns:
    imc username and password. sys.exit() if checks fails.
    """
    try:
        credentials_imc = keyring.get_credential(keyring_entry_imc, imc_username)
        imc_username = credentials_imc.username
        imc_password = credentials_imc.password
        return imc_username, imc_password
    except AttributeError:
        print(f'IMC credentials are not proper set. Using keystore entry: "{keyring_entry_imc}" '
              f'Please check your keystore / credentials manager')
        sys.exit()


def check_prtg_credentials(keyring_entry_prtg, imc_username):
    """

    Args:
        keyring_entry_prtg:
        imc_username:

    Returns:
    PRTG username and password. sys.exit() if checks fails.
    """
    try:
        credentials_prtg = keyring.get_credential(keyring_entry_prtg, imc_username)
        prtg_username = credentials_prtg.username
        prtg_passhash = credentials_prtg.password
        return prtg_username, prtg_passhash
    except AttributeError:
        print(f'PRTG credentials are not proper set. Using keystore entry: "{keyring_entry_prtg}" '
              f'Please check your keystore / credentials manager')
        sys.exit()


def get_current_date():
    """
    return the current date in format: DD/MM/YYYY
    """
    today = datetime.today()
    yyyy = today.year
    mm = today.month
    dd = today.day
    date = f"{dd}/{mm}/{yyyy}"
    return date


def get_current_date_filename():
    """
    return the current date in format: {yyyy}_{mm}_{dd}_{hh}_{minute}
    can be used for creating the logfile filename
    """
    today = datetime.today()
    yyyy = today.year
    mm = today.month
    dd = today.day
    hh = str(today.hour)
    minute = str(today.minute)
    date = f"{yyyy}_{mm}_{dd}_{hh.zfill(2)}_{minute.zfill(2)}"
    return date


def get_imc_keyring_credentials(imc_keyring_description, imc_keyring_username) -> tuple:
    """
    gets/checks IMC credentials at local keystore

    Returns:
    list(imc_username, imc_password)
    """
    # check if the credentials are proper set at the keystore:
    try:
        credentials_imc = keyring.get_credential(imc_keyring_description, imc_keyring_username)
        imc_username = credentials_imc.username
        imc_password = credentials_imc.password
        return imc_username, imc_password
    except AttributeError:
        print(f'IMC credentials are not proper set. Using keystore entry: "{imc_keyring_description}" '
              f'Please check your keystore / credentials manager')
        sys.exit()


def get_prtg_keyring_credentials(prtg_keyring_description, prtg_keyring_username) -> tuple:
    """
    gets/checks PRTG credentials at local keystore

    Returns:
    list(prtg_username, prtg_passhash)

    """
    try:
        credentials_prtg = keyring.get_credential(prtg_keyring_description, prtg_keyring_username)
        prtg_username = credentials_prtg.username
        prtg_passhash = credentials_prtg.password
        return prtg_username, prtg_passhash
    except AttributeError:
        print(f'PRTG credentials are not proper set. Using keystore entry: "{prtg_keyring_description}" '
              f'Please check your keystore / credentials manager')
        sys.exit()
