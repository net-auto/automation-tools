import os
from pathlib import Path

import click
# using corresponding keychain for the credentials:
import keyring

from modules import config_generator

# variables:
CSV_DIR = 'templates/csv/NEW_SITE/'
CSV_PATH = Path.cwd() / CSV_DIR

TEMPLATE_DIR = 'templates/'
TEMPLATE_PATH = Path.cwd() / TEMPLATE_DIR
TEMPLATE_FILE_5130 = TEMPLATE_PATH.absolute() / '5130_baseline_v2.jinja2'
TEMPLATE_FILE_5710_5940 = TEMPLATE_PATH.absolute() / '5900_5700_baseline_v2.jinja2'

SAVE_PATH = Path.cwd() / "CONFIG_OUTPUT"

HOSTNAME_FILE_NAME = open("NEW_HOSTNAMES.txt", "a")
SINGLE_DEVICE_RESULT = dict()
# set the corresponding service_name and username:
env_username = os.getenv("IMC_USER")
credentials = keyring.get_credential("ad_login", env_username)
IMC_USERNAME = credentials.username
IMC_PASSWORD = credentials.password


# cli menu section:
@click.command()
@click.option('--dummy', default=False, help='generate template with generic data')
def main(dummy):
    # gui_selection = config_generator.show_selection_gui()
    # instantiate logger obj:
    # now we will Create and configure logger:
    logger = \
        config_generator.create_logging_instance(
            log_filename="new_created_switches.log"
        )
    # select the data source CSV file:
    # user_input = config_generator.show_selection_gui()
    # check if CSV input variable is set:
    if dummy:
        print("DUMMY FLAG WAS SET")
        # try:
        # set dummy file path:
        csv_dummy_file_path = Path(CSV_PATH, 'DUMMY_DATA_FOR_TEMPLATE.csv')
        if csv_dummy_file_path.is_file():
            csv_data_input = csv_dummy_file_path.resolve()
            new_switches = \
                config_generator.generate_new_switch_objects(csv_data_input)
            config_generator.build_root_config_neighbors(new_switches)
            config_generator.build_downlink_config_5130(new_switches)
            # config_generator.build_uplink_lacp_id(new_switches)
            config_generator.build_uplink_hostname(new_switches)
            config_generator.render_config(SAVE_PATH, new_switches, TEMPLATE_FILE_5130, logger)
            config_generator.copy_dummy_template_to_dfs()
        else:
            print("DUMMY TEMPLATE NOT FOUND!")
            print(f"PLEASE CHECK IF THIS PATH: {csv_dummy_file_path.absolute()} is correct.")
        """
        except FileNotFoundError:
            print("DUMMY TEMPLATE NOT FOUND!")
            sys.exit(f"PLEASE CHECK IF THIS PATH: {csv_dummy_file_path} is correct.")
        """
    else:
        csv_data_input = config_generator.show_csv_gui()
        new_switches = \
            config_generator.generate_new_switch_objects(csv_data_input)
        config_generator.build_root_config_neighbors(new_switches)
        config_generator.build_downlink_config_5130(new_switches)
        # config_generator.build_uplink_lacp_id(new_switches)
        config_generator.build_uplink_hostname(new_switches)
        config_generator.render_config(SAVE_PATH, new_switches, TEMPLATE_FILE_5130, logger)


if __name__ == "__main__":
    main()
    print("FINISHED")
