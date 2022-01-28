import click

from modules.common_functions import *
from modules.ruckus import *

# from functions.api.RUCKUS_API_calls import SZ_API_calls

# global vars:
host = "<WLC_FQDN>"
requiredSoftware = '5.2.2.0.1026'
#
# rollback to the previous version only works,
# if the AP zone was at this release before:
rollback_version = '3.6.2.0.695'
#
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
# affected_ap_zone_name = "postan_60210118"  # example: "AP_GROUP_LAB"
log_filename = f"{get_current_date_filename()}_{Path(__file__).stem}.log"


@click.command()
@click.option('--imc-username', help='IMC username', required=True)
@click.option('--ap-zone', help='name of the AP zone to be upgraded', required=True)
@click.option('--keyring-username', help='username name entry at the credentials manager', required=True)
@click.option('--e-mail-recipient', help='enter the e-mail recipient for the execution report', required=True)
@click.option('--dry-run', default=True, help='perform test run without upgrading/changing the zone')
@click.option('--rollback', default=False, help=f'only works, if zone was the release: {rollback_version} before!!!')
def main(keyring_username, imc_username, e_mail_recipient, dry_run, ap_zone, rollback):
    logger_obj, filename_full_path = create_logging_instance(log_filename)
    credentials = keyring.get_credential(keyring_username, imc_username)
    sz_user = f"{credentials.username}@nps"
    sz_password = credentials.password
    token = get_token(sz_user, sz_password)
    # get the specific AP zone and reassign some values:
    affected_ap_zone = create_specific_ap_zone(ap_zone, token)
    zone_name = affected_ap_zone[0].zone_name
    zone_version = affected_ap_zone[0].zone_details["version"]
    zone_id = affected_ap_zone[0].zone_id
    #
    # log messages for the AP stats:
    # write to log, if the dry_run flag was set to True:
    if dry_run:
        logger_obj.info(f'{10 * "-"} TEST RUN MODE: ')
    logger_obj.info(f'{10 * "-"} Upgrade for AP zone: "{zone_name}" has been started...')
    logger_obj.info(f'{10 * "-"} Current firmware version is: "{zone_version}"')
    logger_obj.info(f'{100 * "-"}')
    #
    # print ap count / status per AP group:
    # count total count for the whole AP group:
    ap_group_total_count = 0
    ap_group_total_count_online = 0
    ap_group_total_count_offline = 0
    ap_group_total_count_flagged = 0
    for ap_group in affected_ap_zone[0].ap_groups:
        logger_obj.info(f'{10 * "-"} AP group name: "{ap_group["name"]}" ')
        logger_obj.info(f'{60 * "-"}')
        logger_obj.info(f'{10 * "-"} APs online in this group: "{ap_group["online_device_count"]}"')
        logger_obj.info(f'{60 * "-"}')
        logger_obj.info(f'{10 * "-"} APs offline in this group: "{ap_group["offline_device_count"]}"')
        if ap_group["offline_device_names"]:
            logger_obj.info(f'{10 * "-"} offline AP(s) hostname(s):')
            for offline_hostname in ap_group["offline_device_names"]:
                logger_obj.info(f'{10 * "-"} >> "{offline_hostname}" <<')
        logger_obj.info(f'{60 * "-"}')
        logger_obj.info(f'{10 * "-"} APs flagged in this group: "{ap_group["flagged_device_count"]}"')
        logger_obj.info(f'{60 * "-"}')
        logger_obj.info(f'{10 * "-"} Summary of the APs in this group (online/flagged/offline):'
                        f' "{ap_group["total_ap_count"]}"')
        logger_obj.info(f'{60 * "-"}')
        logger_obj.info(f'{10 * "-"} Total client count in this group: '
                        f'"{query_client_count_ap_group(ap_group_id=ap_group["id"], token=token)}"')
        ap_group_total_count += ap_group["total_ap_count"]
        ap_group_total_count_online += ap_group["online_device_count"]
        ap_group_total_count_offline += ap_group["offline_device_count"]
        ap_group_total_count_flagged += ap_group["flagged_device_count"]
        logger_obj.info(f'{100 * "-"}')
    # log total count for the whole AP group:
    logger_obj.info(f'{10 * "-"} Total count of all APs in this AP zone '
                    f'(online/flagged/offline): "{ap_group_total_count}"')
    logger_obj.info(f'{10 * "-"} Total count of online APs in this AP zone: "{ap_group_total_count_online}"')
    logger_obj.info(f'{10 * "-"} Total count of offline APs in this AP zone: "{ap_group_total_count_offline}"')
    logger_obj.info(f'{10 * "-"} Total count of flagged APs in this AP zone: "{ap_group_total_count_flagged}"')
    logger_obj.info(f'{100 * "-"}')
    # print(affected_ap_zone)
    # set the firmware version and check, if a rollback flag is set to True:
    if rollback:
        firmware = rollback_version
        logger_obj.info(f'{10 * "-"} rollback flag was set! ')
        logger_obj.info(f'{10 * "-"} rollback to version: {rollback_version} will be checked/performed...')
    else:
        firmware = requiredSoftware
    result = upgrade_zone_firmware(
        zone_id=zone_id,
        required_firmware=firmware,
        token=token,
        current_zone_fw=zone_version,
        dry_run_flag=dry_run,
        zone_name=zone_name
    )
    #
    logger_obj.info(f'{10 * "-"}{result}')
    logger_obj.info(f'{100 * "-"}')
    logger_obj.info(f'{10 * "-"}Finished the script execution.')
    #
    # sendmail status before upgrade procedure:
    mail_subject = "Report: Zone Status"
    send_mail(
        payload=filename_full_path,
        mail_receivers=e_mail_recipient,
        mail_subject=mail_subject,
        from_header=f"AP zone upgrade tool")


if __name__ == "__main__":
    main()
