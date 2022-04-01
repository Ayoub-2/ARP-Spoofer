import netifaces as nf 
from termcolor import colored
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

INFO = lambda x :  colored('[+] ' + x, 'green')
DANGER = lambda x : colored('[!] ' + x, 'red') 
BLUE = lambda x : colored(x , 'blue')
victim_alive = False


def getnetwork(interface = None) :
	if not interface : 
		iface_default = nf.gateways()['default'][2][1]
		addr = nf.ifaddresses(iface_default)[2][0]["addr"]
		mask = nf.ifaddresses(iface_default)[2][0]["netmask"]
		broadcast = nf.ifaddresses(iface_default)[2][0]["broadcast"]
	else : 
		addr = nf.ifaddresses(iface_default)[2][0]["addr"]
		mask = nf.ifaddresses(iface_default)[2][0]["netmask"]
		broadcast = nf.ifaddresses(iface_default)[2][0]["broadcast"]
	return iface_default , addr , mask , broadcast

def getmac(ip):
	arp_request = ARP(pdst=ip)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	try : 
		answered_list = srp(arp_request_broadcast, timeout=1,
								verbose=False)[0]
		return answered_list[0][1].hwsrc
	except IndexError :
		return False


def check_connection(ip) :  
	ans, unans = sr(IP(dst=ip)/ICMP() , verbose=0 , timeout = 2)
	if ans.res == [] and getmac(ip) == False :
		return False
	else :
		return True
	

def gateway() : 
	gws = nf.gateways()
	ip_default_getway = gws['default'][nf.AF_INET][0]
	return ip_default_getway


if __name__ == "__main__" : 
	gw = gateway()
	iface , addr , mask , bd = getnetwork()
	print("gw  :"  , gw)
	print("addr :" , addr)
	print("mask :" , mask)
	print("bd :" , bd)
	check_connection("9.9.9.1")
