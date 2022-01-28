# Requirements IRF auto configuration:

## DHCP:

- option 66 = TFTP server
- option 67 = irf_auto_configurator.py

## TFTP:

- should provide the following files:
    - irf_auto_configurator.py
    - irf_members_mapping.txt with the following content:
        - `<MEMBER_ID>:<SWITCH_SERIAL_NUMBER>:MGMT_VLAN_ID:MGMT_IP_ADDRESS`
        - Example:
            - `1:DPPMWWB76:100:192.168.10.10`

    