from scapy.all import Ether , ARP , srp , conf
import sys , argparse , time

def arp_scan(iface , netmap):
	print("\t\t[+] Scanning {} on interface {}".format(netmap,iface))
	curr_time = time.time()
	print("\t\t[+] Scan started at {} ".format(time.ctime(curr_time)))
	conf.verb = 0
	broadcast_mac = "ff:ff:ff:ff:ff:ff"
	ether_layer = Ether(dst=broadcast_mac)
	arp_layer = ARP(pdst=netmap)
	packet = ether_layer/arp_layer
	ans , unans = srp(packet , iface=iface , timeout=2 , inter=0.1)
	for snd ,rcv in ans:
		print("\t\t" + rcv[ARP].psrc + " : " + rcv[Ether].src)
	print("\t\t[+] Scan Completed at {} and it take {}".format(time.ctime(time.time()) , time.time() - curr_time))

def is_root():
	return os.getuid() == 0

if is_root() == False:
	print("\t\t[+]You Must To be root to run this")
	sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument("-n" , "--network" , help="the Network address is needed")
parser.add_argument("-i" , "--interface" , help="the Network address is needed")
args = parser.parse_args()
iface = args.interface
netmap = args.network

try:
	arp_scan(iface , netmap)
except:
	print("Check Connection")
