from scapy.all import IP , ICMP , sr1 , ls
import sys , argparse , os

def is_root():
	return os.getuid() == 0

if is_root() == False:
        print("\t\t[+]You Must To be root to run this")
        sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument("-s" , "--src-ip" , help="the source ip is needed")
parser.add_argument("-d" , "--dest-ip" , help="the destination ip is needed")
args = parser.parse_args()
try:
	ip_layer = IP(src=args.src_ip , dst=args.dest_ip)
	#print(ls(ip_layer))
	#print(ip_layer.show())
	icmp_req = ICMP()
	#print(icmp_req.show())
	packet = ip_layer / icmp_req
	#print(packet.show())
	print(packet.summary())
	recv_pack = sr1(packet)
	if recv_pack :
		#print(recv_pack.summary())
		print(recv_pack.show())
except:
	print("Check Connection")
