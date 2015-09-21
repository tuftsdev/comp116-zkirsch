# Set0.pcap #

1. 861
2. FTP
3. Files aren't encrypted so they can be easily read/reconstructed if intercepted.
4. SFTP, HTTPS
5. 192.168.1.8
6. user: defcon, password: m1ngisablowhard
7. 6
8.
   - COaqQWnU8AAwX3K.jpg.
   - CDkv69qUsAAq8zN.jpg.
   - CNsAEaYUYAARuaj.jpg.
   - CLu-m0MWoAAgjkr.jpg.
   - CKBXgmOWcAAtc4u.jpg.
   - CJoWmoOUkAAAYpx.jpg.


# Set2.pcap #
10. 77982
11. 12 total (11 anonymous)
12. Used:
    - ettercap -T -r set1.pcap | grep *SEARCH\_STRING*. This was unsuccessful
      for finding anonymous logins.
    - dsniff -p set2.pcap
13.
    - IMAP | 76.0d.78.57.d6.net | dom.bg | Port 143
    - SNMP | 192.168.1.200      |   ?    | Port 161
    - SNMP | 192.168.15.12      |   ?    | Port 161
    - SNMP | 192.168.15.12      |   ?    | Port 161
    - SNMP | 192.168.15.12      |   ?    | Port 161
    - SNMP | 10.5.10.10         |   ?    | Port 161
    - SNMP | 10.5.10.10         |   ?    | Port 161
    - SNMP | 10.5.10.10         |   ?    | Port 161
    - SNMP | 10.5.10.10         |   ?    | Port 161
    - SNMP | 192.168.1.3        |   ?    | Port 161
    - SNMP | 192.168.1.3        |   ?    | Port 161
    - SNMP | 10.150.23.31       |   ?    | Port 161

    Could not reverse DNS of the anonymous logins
14. Valid. Followed TCP Stream from login in Wireshark and could see emails
    (e.g. one from Sunglasses Store, service@greatestsunglassel.us).
   
 
# Set3.pcap #





# General Questions #
19. 
20. Use secured and encrypted protocols! HTTPS, SSL, SFTP, etc.
