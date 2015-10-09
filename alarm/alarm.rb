require 'packetfu'

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

# only fin flag set
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

def is_nmap_scan(pkt)
	if pkt.payload.include?("nmap")
		return true
	else
		return false
	end
end

def is_nikto_scan(pkt)
	return true
end

# credit card regex: http://regular-expressions.mobi/creditcard.html
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

def print_incident(pkt, incident, inc_num)
	puts "#{inc_num}. ALERT: #{incident} is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})!\n"
end

def report_incidents(pkt, inc_num)
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

stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
inc_num = 0
stream.stream.each do |p|
	pkt = PacketFu::Packet.parse(p)
	
	if (pkt != nil)
		inc_num = report_incidents(pkt, inc_num)
		if pkt.tcp_flags != nil
			puts "#{pkt.tcp_flags}"
		end
	end
end
