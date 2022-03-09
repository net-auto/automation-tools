# Requirements IRF auto configuration:

## DHCP: 
- option 66 = TFTP server
- option 67 = irf_auto_configurator.py
 
## TFTP:
- should provide the following files:
  - irf_auto_configurator.py
  - irf_members_mapping.txt with the following content:
    - Member 1:
      - `<MEMBER_ID>:<SWITCH_SERIAL_NUMBER><MGMT_VLAN_ID`
      - Example (Member 1):
        - `1:DPPMWWB76:110`
    - Member X:
      - `<MEMBER_ID>:<SWITCH_SERIAL_NUMBER>`
      - Example (Member X):
        - `2:DPPMWWB77`

    