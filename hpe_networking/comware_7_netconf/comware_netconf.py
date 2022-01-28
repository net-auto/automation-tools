"""
netconf functions for use with comware 7 devices
"""
# imports:
import xmltodict


def get_irf_members(ncclient_manager_ref):
    """

    :param ncclient_manager_ref: ncclient manager reference:
    :return: Current IRF members
    """

    filter_criteria = '''
                <top
                    xmlns="http://www.hp.com/netconf/config:1.0">
                    <IRF>
                        <Members></Members>
                    </IRF>
                </top> 
                '''
    # get-config RPC against the running datastore using a subtree filter
    reply = ncclient_manager_ref.get_config('running', filter=('subtree', filter_criteria))
    data = xmltodict.parse(reply.data_xml)
    if data.get('data').get('top'):
        return data.get('data')['top']['IRF']['Members']['Member']
    else:
        return f'no IRF members data found!'


def get_irf_interfaces(ncclient_manager_ref):
    """

    :param ncclient_manager_ref: ncclient manager reference
    :return: Current IRF interfaces
    """

    filter_criteria = '''
                <top
                    xmlns="http://www.hp.com/netconf/config:1.0">
                    <IRF>
                        <IRFPorts></IRFPorts>
                    </IRF>
                </top> 
                '''
    # get-config RPC against the running datastore using a subtree filter
    reply = ncclient_manager_ref.get_config('running', filter=('subtree', filter_criteria))
    data = xmltodict.parse(reply.data_xml)
    if data.get('data').get('top'):
        return data.get('data')['top']['IRF']['IRFPorts']['IRFPort']
    else:
        return f'no IRF interfaces data found!'


def get_vlans(ncclient_manager_ref):
    """

    :param ncclient_manager_ref: ncclient manager reference
    :return: Current VLANs configured
    """

    filter_criteria = '''
                <top
                    xmlns="http://www.hp.com/netconf/config:1.0">
                    <VLAN>
                        <VLANs></VLANs>
                    </VLAN>
                </top>
                '''
    # get-config RPC against the running datastore using a subtree filter
    reply = ncclient_manager_ref.get_config('running', filter=('subtree', filter_criteria))
    # reply = ncclient_manager_ref.action(filter_criteria)
    data = xmltodict.parse(reply.data_xml)
    if data.get('data').get('top'):
        return data.get('data')['top']['VLAN']['VLANs']
    else:
        return f'no VLANs data found!'
