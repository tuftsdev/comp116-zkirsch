# Comp 116: Security #
## Assignment 2: The Incident Alarm ##
### Zach Kirsch ###
### 13 October 2015 ###
&nbsp;

I believe that all aspects of the assignment, including the extra credit, have been correctly implemented:
- Running **ruby alarm.rb** reads in packets in realtime and looks for malicious scans
  - Nikto
  - X-Mas
  - NULL
  - FIN
  - Other Nmap
- Running **ruby alarm.rb -p &lt;pcap file&gt;** reads in a pcap file, and searches for the same malicious scans as running **ruby alarm.rb** with no command line options.
- Running **ruby alarm.rb -r &lt;web server log&gt;** reads in a server log in Apache combined log or common log format, and looks for the following incidents:
  - Nmap scan (of any variety)
  - Nikto scan
  - Someone running Rob Graham's Masscan
  - Someone scanning for Shellshock vulnerability
  - Anything pertaining to phpMyAdmin
  - Anything that looks like shellcode

I collaborated, but did not share code, with a small group of students:
- Danielle Zelin
- Michael Seltzer
- Michael Jacobson
- Becky Cutler
- Daniel Baigel

I spent about 6 hours on this assignment.
&nbsp;&nbsp;

*Are the heuristics used in this assignment to determine incidents "even that good"?*

For detecting certain scans/attacks that deal with switching TCP flags on and off, this is effective at analyzing the flags on individual packets. However, for other types of scans, searching for string and binary matches is a rudimentary effort at identifying scans. It would be more effective to analyze what the scan is actually doing, but that can be substantially more difficult.
Additionally, searching for credit card leaks has an inordinate number of false positives. Many cookies contain long strings that match the regular expressions used to identify credit cards.
&nbsp;

*If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?*

I would attempt to
- categorize more types of scans and attacks, rather than just output "Other Nmap scan"
- search for passwords and/or usernames sent in plain text
- include better error reporting (output to file, store in database, or even send e-mail when there is an incident)
- include support for non-Apache server logs
