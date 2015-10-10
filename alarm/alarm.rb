#############################################################################
#                         Comp 116 | HW 2 | Alarm                           # 
#                        Zach Kirsch, October 2015                          # 
#                                                                           #      
# This is a program that acts as an alarm for nmap scans and other          #
#   vulnerabilities.                                                        #
#                                                                           #
#               Usage: ruby alarm.rb [-r <web server log>]                  #
#                                                                           #
# If run without the -r option, this will analyze TCP packets in real time, #
# sounding the alarm if any of the following are detected:                  #
#  - Nikto scan                                                             #
#  - X-MAS scan                                                             #
#  - NULL scan                                                              #
#  - FIN scan                                                               #
#  - Any other nmap scan                                                    #
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

require 'packetfu'

                         ###########################
			 # Functions for detecting #
			 #        TCP Scans        #
			 ###########################

# Detects X-MAS scan - if urg, psh, and fin are all lit
def is_xmas_scan(pkt)
	if ! pkt.proto.include?("TCP")
		return false
	end

	if pkt.tcp_flags.urg == 0
		return false
	end
	
	if pkt.tcp_flags.psh == 0
		return false
	end
	
	if pkt.tcp_flags.fin == 0
		return false
	end
	
	return true
end

# Detects NULL scan - if all the bits are 0, it's a NULL scan
def is_null_scan(pkt)
	if ! pkt.proto.include?("TCP")
		return false
	end
	
	if pkt.tcp_flags.fin == 1
		return false
	end

	if pkt.tcp_flags.ack == 1
		return false
	end
	
	if pkt.tcp_flags.rst == 1
		return false
	end
	
	if pkt.tcp_flags.syn == 1
		return false
	end

	if pkt.tcp_flags.psh == 1
		return false
	end

	if pkt.tcp_flags.urg == 1
		return false
	end

	return true
end

# Detects FIN scan - only fin flag set
def is_fin_scan(pkt)
	if ! pkt.proto.include?("TCP")
		return false
	end

	if pkt.tcp_flags.fin != 1
		return false
	end

	if pkt.tcp_flags.ack == 1
		return false
	end
	
	if pkt.tcp_flags.rst == 1
		return false
	end
	
	if pkt.tcp_flags.syn == 1
		return false
	end

	if pkt.tcp_flags.psh == 1
		return false
	end

	if pkt.tcp_flags.urg == 1
		return false
	end

	return true
end

# Detects nmap scan - if nmap is anywhere in the payload, then
# it's probably an nmap scan
def is_nmap_scan(pkt)
	if pkt.payload.include?("nmap")
		return true
	else
		return false
	end
end

def is_nikto_scan(pkt)
	return true
	# TODO
end



                         ##########################
			 # Function for detecting #
			 #      credit cards      #
			 ##########################

# detects credit card by searching for regexp's.
# (thanks to http://regular-expressions.mobi/creditcard.html for the regex)
def is_credit_card_leak(pkt)
	body = {pkt.payload}
	
	# visa
	if (/^4[0-9]{12}(?:[0-9]{3})?$/.match(body) != 0)
		return true;

	# mastercard
	if (/^5[1-5][0-9]{14}$/.match(body) != 0)
		return true;

	# american express
	if (/^3[47][0-9]{13}$/.match(body) != 0)
		return true;

	# diner's club
	if (/^3(?:0[0-5]|[68][0-9])[0-9]{11}$/.match(body) != 0)
		return true;

	# discover
	if (/^6(?:011|5[0-9]{2})[0-9]{12}$/.match(body) != 0)
		return true;

	# JCB
	if (/^(?:2131|1800|35\d{3})\d{11}$/.match(body) != 0)
		return true;

	return false
end




                         ##########################
			 # Function for analyzing #
			 #         web logs       #
			 ##########################


def is_masscan(pkt)
	return true
	# TODO
end

def is_shellshock_search(pkt)
	return true
	# TODO
end

def is_phpmyadmin_search(pkt)
	return true
	# TODO
end

def is_shellcode(pkt)
	return true
	# TODO
end

                         ##########################
			 #   Incident Reporting   #
			 ##########################


def print_incident(pkt, incident, inc_num)
	puts "#{inc_num}. ALERT: #{incident} is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})!\n"
end

def report_live_incidents(pkt, inc_num)
	orig_inc_num = inc_num

	if is_xmas_scan(pkt)
		print_incident(pkt, "X-MAS Scan", inc_num)
		inc_num += 1
	end

	if is_null_scan(pkt)
		print_incident(pkt, "NULL Scan", inc_num)
		inc_num += 1
	end

	if is_fin_scan(pkt)
		print_incident(pkt, "FIN Scan", inc_num)
		inc_num += 1
	end

	if orig_inc_num == inc_num and is_nmap_scan(pkt)
		print_incident(pkt, "Other Nmap Scan", inc_num)
		inc_num += 1
	end

	if is_nikto_scan(pkt)
		print_incident(pkt, "Nikto Scan", inc_num)
		inc_num += 1
	end
	
	if is_credit_card_leak(pkt)
		print_incident(pkt, "Credit card leak", inc_num)
		inc_num += 1
	end

	return inc_num
end

def report_log_incidents(pkt, inc_num)
	if is_nmap_scan(pkt)
		print_incident(pkt, "Nmap Scan", inc_num)
		inc_num += 1
	end

	if is_nikto_scan(pkt)
		print_incident(pkt, "Nikto Scan", inc_num)
		inc_num += 1
	end
	
	if is_masscan(pkt)
		print_incident(pkt, "Rob Graham's Masscan", inc_num)
		inc_num += 1
	end

	if is_shellshock_search(pkt)
		print_incident(pkt, "Shellshock Vulnerability Search", inc_num)
		inc_num += 1
	end

	if is_phpmyadmin_search(pkt)
		print_incident(pkt, "phpMyAdmin Vulnerability Search", inc_num)
		inc_num += 1
	end

	if is_shellcode(pkt)
		print_incident(pkt, "Shellcode", inc_num)
		inc_num += 1
	end

	return inc_num
end


                         ###########################
			 #      Main Program       #
			 ###########################
puts ARGV
stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
inc_num = 0
stream.stream.each do |p|
	pkt = PacketFu::Packet.parse(p)
	
	if (pkt != nil)
		inc_num = report_live_incidents(pkt, inc_num)
	end
end
