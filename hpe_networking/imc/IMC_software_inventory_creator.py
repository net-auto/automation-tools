"""
### Description ###
gets the current devices at IMC and creates a sofware inventory / pie chart svg file

"""
import os

import pygal
from pyhpeimc.auth import *

from modules import common_functions as api

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

if __name__ == "__main__":
    swInventory = api.createSoftwareInventory(IMC_USER, IMC_PASS)

    # count software version occurance:
    versionCount = dict()
    for hostname, version in swInventory.items():
        compareValue = version
        # print(compareValue)
        resultSum = sum(currentValueSw == compareValue for currentValueSw in swInventory.values())
        versionCount[version] = resultSum
        # pie_chart.add(hostname, version)

    # creating line chart object
    pie_chart = pygal.Pie()
    # naming the title
    pie_chart.title = f'Current Software Versions installed, Total devices processed: {len(swInventory)}\n Date created: {api.get_current_date()}'

    # create the pie chart:
    for version, count in versionCount.items():
        pie_chart.add(version, count)
    # pprint(swInventory)

    # render the visualization to svg file:
    filenameDate = f'{api.getCurrentDateFilename()}_software_versions_pie_chart.svg'
    pie_chart.render_to_file(filenameDate)

    print(20 * "-" + "FINISHED" + 20 * "-")
