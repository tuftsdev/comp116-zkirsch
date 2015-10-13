#############################################################################
#                         Comp 116 | HW 2 | Alarm                           #
#                        Zach Kirsch, October 2015                          #
#                                                                           #
# This is a program that acts as an alarm for nmap scans and other          #
#   vulnerabilities.                                                        #
#                                                                           #
#    Usage: ruby alarm.rb { [-r <web server log>], [-p <pcap file>] }       #
#                                                                           #
# If run without any options, this will analyze TCP packets in real time,   #
# sounding the alarm if any of the following are detected:                  #
#  - Nikto scan                                                             #
#  - X-MAS scan                                                             #
#  - NULL scan                                                              #
#  - FIN scan                                                               #
#  - Any other nmap scan                                                    #
#                                                                           #
# If run with the -p option, this will read in a pcap file instead of a     #
# live packet stream, sounding the alarm if any of the above scans are      #
# detected.                                                                 #
#                                                                           #
# If run with the -r option, this will read in a web server log and sound   #
# the alarm if any of the following are detected:                           #
#  - NMAP scan (of any variety)                                             #
#  - Nikto scan                                                             #
#  - Someone running Rob Graham's Masscan                                   #
#  - Someone scanning for Shellshock vulnerability                          #
#  - Anything pertaining to phpMyAdmin                                      #
#  - Anything that looks like shellcode                                     #
#                                                                           #
# TCP attack definitions are based on:                                      #
#   https://nmap.org/book/man-port-scanning-techniques.html                 #
#############################################################################

require 'rubygems'
require 'packetfu'
require 'pcaprub'
require 'apachelogregex'


                         ###########################
                         #    Matching function    #
                         ###########################

# checks if a 'needle' (a string) is somewhere in a 'haystack', where the
# haystack may or may not be in binary. When performing a binary search, this
# compares the binary version of the needle (without changing case) to
# the haystack. When comparing as strings, the third parameter determines
# whether the search should be case insensitive.
def matches?(haystack, needle, case_sens)

        # maybe haystack isn't binary
        case_sens ? regex = /#{needle}/ : regex = /#{needle}/i
        if haystack.match(regex) != nil
                return true
        end

        # maybe the haystack is binary
        binary_needle = needle.each_byte.map { |b| sprintf(" 0x%02X ",b) }.join
        if haystack.match(binary_needle) != nil
                return true
        end

        return false
end


                         ###########################
                         # Functions for detecting #
                         #        TCP Scans        #
                         ###########################

# Detects X-MAS scan - if urg, psh, and fin are all lit
def is_xmas_scan?(pkt)
        if ! pkt.proto.include?("TCP")
                return false
        end

        return ( pkt.tcp_flags.fin == 1 and
                 pkt.tcp_flags.psh == 1 and
                 pkt.tcp_flags.urg == 1 )
        
        return true
end

# Detects NULL scan - if all the bits are 0 it is a NULL scan
def is_null_scan?(pkt)
        if ! pkt.proto.include?("TCP")
                return false
        end
        
        return ( pkt.tcp_flags.fin == 0 and
                 pkt.tcp_flags.ack == 0 and
                 pkt.tcp_flags.rst == 0 and
                 pkt.tcp_flags.syn == 0 and
                 pkt.tcp_flags.psh == 0 and
                 pkt.tcp_flags.urg == 0 )
end

# Detects FIN scan - only fin flag set
def is_fin_scan?(pkt)
        if ! pkt.proto.include?("TCP")
                return false
        end

        return ( pkt.tcp_flags.fin == 1 and
                 pkt.tcp_flags.ack == 0 and
                 pkt.tcp_flags.rst == 0 and
                 pkt.tcp_flags.syn == 0 and
                 pkt.tcp_flags.psh == 0 and
                 pkt.tcp_flags.urg == 0 )
end

# Detects nmap scan - if nmap is anywhere in the payload, then
# it is probably an nmap scan.
def is_nmap_scan?(payload)
        return matches?(payload, "Nmap", true)
end

# Detects nikto scan - if nikto is anywhere in the payload, then
# it is probably a nikto scan. If the request is using a HEAD HTTP
# request, then it could be a Nikto scan (by probing for files)
def is_nikto_scan?(payload)
        return (matches?(payload, "HEAD", true) or
                matches?(payload, "Nikto", false))
end



                         ##########################
                         # Function for detecting #
                         #      credit cards      #
                         ##########################

# detects credit card by searching for regexp.
# (thanks to http://regular-expressions.mobi/creditcard.html for the regex)
def is_credit_card_leak?(pkt)
        body = pkt.payload
        
        # visa
        if body.match(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
                return true;
        end     

        # mastercard
        if body.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
                return true;
        end     

        # american express
        if body.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/) != nil
                return true;
        end     

        # discover
        if body.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
                return true;
        end     

        return false
end




                         ##########################
                         # Function for analyzing #
                         #        web logs        #
                         ##########################


# if 'masscan' is in the request, then it's probably Rob Graham's Masscan
def is_masscan?(log)
        return log.match(/masscan/i)
end

# if there's /bin/ requests, it's probably shellshock
def is_shellshock_search?(log)
        return (log.match(/\/bin\//) != nil or
                log.match(/\s*{\s*:\s*;\s*}\s*;/) != nil)
end

# if there's phpMyAdmin in the request, then that's a red flag
def is_phpmyadmin_search?(log)
        return log.match(/phpMyAdmin/) != nil
end

# if there's \x in the requests, it's probably trying to run some shellcode
def is_shellcode?(log)
        return log.match(/\\x/) != nil
end






                         ##########################
                         #   Incident Reporting   #
                         ##########################

def print_incident(inc_num, incident, ip_saddr, proto, payload)
        to_print =  "#{inc_num}. ALERT: #{incident} is detected from"\
                    " #{ip_saddr} (#{proto}) (#{payload})!\n"
        puts to_print
end

def print_pkt_incident(pkt, incident, inc_num)
        print_incident(inc_num, incident, \
                       pkt.ip_saddr, pkt.proto.last, pkt.payload)
end

# searches log request for, and returns, protocol
def get_proto_from_log(log)
        proto = ""
        req = log["%r"]

        if    req.match(/HTTPS/) != nil
                proto = "HTTPS"
        elsif req.match(/HTTP/)  != nil
                proto = "HTTP"
        elsif req.match(/UDP/)   != nil
                proto = "UDP"
        elsif req.match(/TCP/)   != nil
                proto = "TCP"
        elsif req.match(/SFTP/)  != nil
                proto = "SFTP"
        elsif req.match(/FTP/)   != nil
                proto = "FTP"
        elsif req.match(/IMAP/)  != nil
                proto = "IMAP"
        elsif req.match(/POP/)   != nil
                proto = "POP"
        elsif req.match(/SMTP/)  != nil
                proto = "SMTP"
        elsif req.match(/SSH/)   != nil
                proto = "SSH"
        end

        return proto
end

def print_log_incident(log, incident, inc_num)
        proto = get_proto_from_log(log)
        print_incident(inc_num, incident, log["%h"], proto, log["%r"]);
end

def report_packet_incidents(pkt, inc_num)
        orig_inc_num = inc_num

        if is_xmas_scan?(pkt)
                print_pkt_incident(pkt, "X-Mas Scan", inc_num)
                inc_num += 1
        end

        if is_null_scan?(pkt)
                print_pkt_incident(pkt, "NULL Scan", inc_num)
                inc_num += 1
        end

        if is_fin_scan?(pkt)
                print_pkt_incident(pkt, "FIN Scan", inc_num)
                inc_num += 1
        end

        if orig_inc_num == inc_num and is_nmap_scan?(pkt.payload)
                print_pkt_incident(pkt, "Other Nmap Scan", inc_num)
                inc_num += 1
        end

        if is_nikto_scan?(pkt.payload)
                print_pkt_incident(pkt, "Nikto Scan", inc_num)
                inc_num += 1
        end
        
        if is_credit_card_leak?(pkt)
                print_pkt_incident(pkt, "Credit card leak", inc_num)
                inc_num += 1
        end

        return inc_num
end

def report_log_incidents(log, inc_num)
        
        log.each do |k, v|
                if is_nmap_scan?(v)
                        print_log_incident(log, "Nmap Scan", inc_num)
                        inc_num += 1
                        break
                end
        end

        if is_nikto_scan?(log["%r"])
                print_log_incident(log, "Nikto Scan", inc_num)
                inc_num += 1
        end
       
	# masscan shows up on User-Agent portion of log file 
        if log["%{User-Agent}i"] != nil and is_masscan?(log["%{User-Agent}i"])
                print_log_incident(log, "Rob Graham's Masscan", inc_num)
                inc_num += 1
        end

        log.each do |k, v|
                if is_shellshock_search?(v)
                        print_log_incident(log,                               \
                                           "Shellshock Vulnerability Search", \
                                           inc_num)
                        inc_num += 1
                        break
                end
        end

        if is_phpmyadmin_search?(log["%r"])
                print_log_incident(log,                               \
                                   "phpMyAdmin Vulnerability Search", \
                                   inc_num)
                inc_num += 1
        end

        log.each do |k, v|
                if is_shellcode?(v)
                        print_log_incident(log, "Shellcode", inc_num)
                        inc_num += 1
                        break
                end
        end

        return inc_num
end

                         ###########################
                         #  Analyzation Functions  #
                         ###########################

def analyze_packet(unparsed_p, inc_num)
	pkt = PacketFu::Packet.parse(unparsed_p)
	new_inc_num = inc_num
	if (pkt != nil)
		new_inc_num = report_packet_incidents(pkt, inc_num)
	end
	return new_inc_num
end

def analyze_live_traffic()
        stream = PacketFu::Capture.new(:start => true,   \
                                       :iface => 'en0', \
                                       :promisc => true)
        inc_num = 0
        stream.stream.each do |p|
		inc_num = analyze_packet(p, inc_num)
        end
end

def analyze_log(logs)
        combined_log_format = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
        common_log_format = '%h %l %u %t \"%r\" %>s %b'
        combined_parser = ApacheLogRegex.new(combined_log_format)
        common_parser = ApacheLogRegex.new(common_log_format)
        
        inc_num = 0
        File.readlines(logs).collect do |l|
                log = combined_parser.parse(l)
                if (log == nil)
                        log = common_parser.parse(l)
                end
                if (log != nil)
                        inc_num = report_log_incidents(log, inc_num)
                end
        end
end

def analyze_pcap(file)
	capture = PCAPRUB::Pcap.open_offline(file)
	inc_num = 0
	capture.each_packet do |p|
		inc_num = analyze_packet(p.data, inc_num)
	end
end

                         ###########################
                         #      Main Program       #
                         ###########################

usage = "Usage: ruby alarm.rb\n"\
        "       ruby alarm.rb -r <web server log>\n"\
	"       ruby alarm.rb -p <pcap file>\n"

if ARGV[0] == "-r"
        if (ARGV[1] != nil)
                analyze_log(ARGV[1])
        else
                abort(usage)
        end
elsif ARGV[0] == '-p'
        if (ARGV[1] != nil)
                analyze_pcap(ARGV[1])
        else
                abort(usage)
        end
elsif ARGV[0] != nil
	abort(usage)
else
        analyze_live_traffic()
end
