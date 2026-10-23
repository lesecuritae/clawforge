import struct,time,socket,pathlib,sys
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%sH'%(len(b)//2),b));n=(n>>16)+(n&65535);n=(n>>16)+(n&65535)
 return (~n)&65535
packets=[]
for i,payload in enumerate([b'CLAWFORGE_IDS_LAB_MARKER',b'ordinary benign traffic',b'CLAWFORGE_IDS_LAB_MARKER']):
 src=socket.inet_aton('203.0.113.8');dst=socket.inet_aton('198.51.100.10')
 udp=struct.pack('!HHHH',41000+i,9999,8+len(payload),0)+payload
 ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),i,0,64,17,0,src,dst)
 ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 packets.append(bytes.fromhex('00112233445566778899aabb0800')+ip+udp)
with (out/'fixture.pcap').open('wb') as f:
 f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
 for i,packet in enumerate(packets):f.write(struct.pack('<IIII',int(time.time()),i*1000,len(packet),len(packet))+packet)
(out/'suricata.rules').write_text('alert udp any any -> any 9999 (msg:"Clawforge controlled IDS lab"; content:"CLAWFORGE_IDS_LAB_MARKER"; sid:1000001; rev:1;)\n')
