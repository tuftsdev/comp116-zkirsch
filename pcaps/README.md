# Comp 116 | Tufts University #
## Assignment 1: Packet Sleuth ##
## Zach Kirsch ##


### Assignment Source ###
http://tuftsdev.github.io/DefenseOfTheDarkArts/assignments/a1.html


### Objectives ###
In this assignment, you will learn how to read and dissect files and sensitive information (including usernames and passwords) from sets of packets captured from a network using freely available tools.


### Overview ###
You are given two sets of packet captures from two different networks in PCAP format to analyze: one from a network where file transfers occurred, and the other from arguably the world's most hostile network, DEF CON in Las Vegas, NV.



## set0.pcap ##

1. 861
2. FTP
3. Files aren't encrypted so they can be easily read/reconstructed if
   intercepted.
4. SFTP
5. 192.168.1.8
6. user: defcon, password: m1ngisablowhard
7. 6
8.
   - COaqQWnU8AAwX3K.jpg
   - CDkv69qUsAAq8zN.jpg
   - CNsAEaYUYAARuaj.jpg
   - CLu-m0MWoAAgjkr.jpg
   - CKBXgmOWcAAtc4u.jpg
   - CJoWmoOUkAAAYpx.jpg


## set2.pcap ##

10. 77982
11. 1
12. Used:
    - ettercap -T -r set1.pcap | grep *SEARCH\_STRING*.
      - Search strings used: pass, PASS, user, USER, username, USERNAME,
        email, EMAIL, e-mail, E-MAIL, login, LOGIN, auth, AUTH, session,
        SESSION
    - dsniff -p set2.pcap
13.
    - IMAP | 87.120.13.118 | 76.0d.78.57.d6.net | Port 143
14. It is valid.
   
 
## set3.pcap ##
15. 2
16. 
    - HTTP | 172.222.171.208 | forum.defcon.org | Port 80
    - HTTP | 54.191.109.23 | ec2-54-191-109-23.us-west-2.compute.amazonaws.com |
      Port 80
17.
    - 1 legitimate, 1 illegitimate
18. Methodology: tshark -r <input.pcap> -T fields -e ip.dst ip.src | sort | uniq
    Source: https://ask.wireshark.org/questions/4827/determining-unique-mac-and-ip-addresses-in-a-pcap
    - 10.0.8.253
    - 10.0.8.254
    - 10.102.0.1
    - 10.102.15.110
    - 10.102.15.200
    - 10.102.15.200
    - 10.102.0.1
    - 10.102.15.50
    - 10.102.15.51
    - 10.102.15.55
    - 10.102.15.57
    - 10.102.15.57
    - 216.222.82.67
    - 10.102.31.255
    - 10.103.15.115
    - 10.103.15.13
    - 10.103.15.135
    - 10.103.15.166
    - 10.103.15.184
    - 10.103.15.21
    - 10.103.15.4
    - 10.103.15.47
    - 10.103.15.92
    - 10.104.15.214
    - 10.104.15.219
    - 10.104.15.229
    - 10.104.15.240
    - 10.104.15.241
    - 10.107.15.239
    - 10.107.15.246
    - 192.168.1.3
    - 10.110.15.205
    - 10.110.15.206
    - 10.110.15.209
    - 10.113.15.137
    - 10.113.15.138
    - 10.113.15.139
    - 10.113.15.164
    - 10.113.15.173
    - 10.114.15.108
    - 10.114.15.150
    - 10.114.15.98
    - 10.115.15.193
    - 10.115.15.200
    - 10.115.15.203
    - 10.115.15.209
    - 10.115.15.213
    - 10.116.15.220
    - 10.116.15.220
    - 10.0.8.253
    - 10.116.15.220
    - 10.0.8.254
    - 10.116.15.231
    - 10.117.15.158
    - 10.117.15.160


# General Questions #
19. Followed TCP Stream from login in Wireshark.
    - For set2.pcap, reconstructed emails that seemed legitimate).
      (e.g. one from Sunglasses Store, service@greatestsunglassel.us).
    - For set3.pcap, 1 illegitimate (403 Forbidden error in response) and
      1 legitimate (lots of 200 OK messages in response)
20. Use secured and encrypted protocols! HTTPS, SSL, SFTP, etc.
