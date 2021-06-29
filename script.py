import os
from datetime import datetime
import itertools
import hashlib
import collections

filename = "name of the txt file - OUTPUT"
filepath = "pcap file path - INPUT"
date = datetime.today().strftime('%Y-%m-%d')
f = open(filename, "w")
f.write("Date of appearance: " + filename.split('.')[0] +" \n\
Date of analyze: " + date + " \n\
Analyzed by: 'Your name' \n\
Threat title: Qakbot \n\
Network file path: " + filename.split('.')[0] +".pcap\n")

# get md5 file hash name
md5_hash = hashlib.md5()
a_file = open(filename, "rb")
content = a_file.read()
md5_hash.update(content)
digest = md5_hash.hexdigest()

## get the file and split sessions

# get all ssl sessions and the fields required in the documentation
ssl_sessions = os.popen("tshark -r " + filepath + " -Y 'tcp.port == 443 || udp.port == 443' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tls.handshake.type -e tls.handshake.extensions_server_name -e tls.record.version -e tls.handshake.ciphersuite -e tls.handshake.extensions_ec_point_format -e tls.handshake.certificate_length -e x509sat.uTF8String -e x509sat.CountryName -e x509sat.printableString -e x509ce.dNSName -e frame.time -e tls.handshake.certificate -e x509af.utcTime -e tls.handshake.extensions_supported_group -E header=n -E separator='|'").read()
ssl_sessions_list = ssl_sessions.split("\n")
ssl_sessions_list_of_list = []
for i in range(0, len(ssl_sessions_list)-1):
	ssl_sessions_list_of_list.append(ssl_sessions_list[i].split('|'))
#print(ssl_sessions_list_of_list)

# get fingerprint of each session and create the mother load
fg_list = []
for i in ssl_sessions_list_of_list:
	ip_src = i[0]
	ip_src = ip_src.replace('.','')
	ip_dst = i[1]
	ip_dst = ip_dst.replace('.','')
	port_src = i[2]
	port_dst = i[3]
	if ip_dst > ip_src:
		fg = ip_src + ip_dst + port_src + port_dst
	else:
		fg = ip_dst + ip_src + port_dst + port_src
	fg_list.append(fg)

# create the mother load list
mother_load = zip(fg_list, ssl_sessions_list_of_list)

# define var
all_minute = 0
all_second = 0
all_k = 0

## create the file
f.write("File hash: " + digest + "\n\n")
f.write("Description: " + filename.split('.')[0] + "\n")
# insert session info
fg_set = set(fg_list)
number_of_session = 1
for k in fg_set:
	session = []
	first_item = k
	for i in mother_load:
		if i[0] == first_item:
			session.append(i[1])
		# append to file session info
	# session number
	f.write("Session number is " + str(number_of_session) + "\n")
	
	# IP addresses
	f.write("Malicious IP: src : " + session[0][0] + " dst : " + session[0][1] + "\n")
	
	# malicious domain
	malicious_domain=''
	for i in session:
		if i[5]!='':
			malicious_domain = i[5]
			f.write("Malicious Domain: " + malicious_domain + "\n")
	if malicious_domain=='':
		f.write("Malicious Domain: empty \n")

	# tls record version
	for i in session:
		if i[6]!='':
			tls_record_version = i[6]
			f.write("TLS version: " + tls_record_version + "\n")
			break

	# cipher suite proposed
	for i in session:
		if i[4]=='1':
			f.write("Cipher Suite list proposed: " + i[7] + "\n")

	# chosen cipher
	for i in session:
		if i[4]=='2':
			f.write("Chosen Cipher Suite: " + i[7] + "\n")

	# elliptic curve point format
	elliptic_curve = ''
	for i in session:
		if i[8]!='':
			elliptic_curve = i[8] + ","
	elliptic_curve_after_edit = elliptic_curve[:-1]
	f.write("Elliptic Curve point format: " + elliptic_curve_after_edit + "\n")

	# supported group
	supported_group = ''
	for i in session:
		if i[17]!='':
			supported_group = i[17] + ""
	supported_group_after_edit = supported_group[:-1]
	f.write("Supported Group: " + elliptic_curve_after_edit + "\n")

	# certifcate info
	f.write("-+-+-Certificate information-+-+- :\n")

	certifcate_length = ''
	for i in session:
		if i[9]!='':
			certifcate_length = certifcate_length + i[9] + ','
	f.write("Certificate length: " + certifcate_length[:-1] + "\n")

	certificate_utf8 = ''
	for i in session:
		if i[10]!='':
			certificate_utf8 = certificate_utf8 + i[10] + ','
	f.write("Certificate UTF-8 string: " + certificate_utf8[:-1] + "\n")

	certifcate_country_name = ''
	for i in session:
		if i[11]!='':
			certifcate_country_name = certifcate_country_name + i[11] + ','
	f.write("Certificate country name: " + certifcate_country_name[:-1] + "\n")

	certificate_printable_string = ''
	for i in session:
		if i[12]!='':
			certificate_printable_string = certificate_printable_string + i[12] + ','
	f.write("Certificate printable string: " + certificate_printable_string[:-1] + "\n")
	
	certificate_dns = ''
	for i in session:
		if i[13]!='':
			certificate_dns = certificate_dns + i[13] + ','
	f.write("Certificate DNS name: " + certificate_dns[:-1] + "\n")

	for i in session:
		if i[15]!='':
			f.write("Certificate: " + i[15] + "\n")
			certificate_list = i[15].split(',')
			hash_list = ''
			for i in certificate_list:
				certificate_object = hashlib.md5(i.encode())
				certificate_hash = certificate_object.hexdigest()
				hash_list = hash_list + certificate_hash + ','
			f.write("Certificate Hash: " + hash_list[:-1] + "\n" )

	for i in session:
		if i[16]!='':
			f.write("Start date: " + i[16].split(',')[0] + "\n")
			f.write("End date: " + i[16].split(',')[1] + "\n")

	# time between packets for each session
	# extract first time from the pcap
	k = 1
	total_seconds = 0
	for i in session:
		if i[14]!='':
			first_time_str = i[14].split(' ')[3]
			first_time_date = datetime.strptime(first_time_str[:-3], '%H:%M:%S.%f')
			break
	for i in session:
		k = k+1
		if k!=1:
			time_str = i[14].split(' ')[3]
			time_date = datetime.strptime(time_str[:-3], '%H:%M:%S.%f')
			time_delta = time_date - first_time_date
			first_time_date = time_date
			time_delta_seconds = time_delta.total_seconds()
			total_seconds = total_seconds + time_delta_seconds
			total_minute = total_seconds/60
			Avg_sec= total_seconds/k
			Avg_min = total_minute/k
			all_minute = all_minute + total_minute
			all_second = all_second + total_seconds
			all_k = all_k + k
	f.write("Time between packets for each session in minute: " + str(Avg_min) + " min\n")
	f.write("Time between packets for each session in seconds: " + str(Avg_sec) + " s\n")

	# clear view in text file
	f.write("\n")
	number_of_session = number_of_session + 1

all_total_min = all_minute/all_k
all_total_second = all_second/all_k
f.write("Total time between packets for all sessions in minute: " + str(all_total_min) + " min\n")
f.write("Total time between packets for all sessions in second: " + str(all_total_second) + " s\n")