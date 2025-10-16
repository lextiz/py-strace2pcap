# py_strace2pcap
convert specific strace output file to pcap using scapy python library

# idea behind:
It would be great if strace could directly write pcap, but it's not that modular to support custom formating.
It would be great if wireshark library could be safely used from strace module to produce pcap output, 
but 3rd party usage of libwireshark is not [encouraged](https://stackoverflow.com/questions/10308127/using-libwireshark-to-get-wireshark-functionality-programmatically).
What is achievable is to make a tool that can read strace output file and generate pcap file - then one can read pcap with wireshark, tcpdump, tshark.

# purpose :
I wanted to check some non encrypted traffic protocol that use binary encoding - it was not observable in ascii. 
It was on production, process is already running. It was in namespace, and not the only process that is running in that namespace.
I was able to strace the process, I knew that I have all the bytes (above tcp layer), and I wanted
to dissect that with tshark to get details of communication. This tool is created for that purpose. 

![example wireshark](https://github.com/comboshreddies/py-strace2pcap/blob/main/images/mongo_find.png?raw=true)


# setup
install needed python module
```console
pip3 install scapy
```
or
```console
pip3 install -r requirements.txt
```

note: you might want to use python venv if you don't want scappy installed globally

# get strace file in specific format
start strace
```console
strace -f -s655350 -o /tmp/straceSample -ttt -T -yy -xx command
```
or for already running process
``` console
strace -f -s655350 -o /tmp/straceSample -ttt -T -yy -xx -p <running_pid>
```

# run py\_strace2pcap.py
start conversion from strace to pcap
```console
py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
```

## UNIX domain sockets

`py_strace2pcap.py` can now synthesise realistic TCP/IP flows for UNIX stream
sockets. Each inode is mapped to a deterministic Ethernet/IP/TCP tuple so that
Wireshark automatically decodes higher-level protocols such as HTTP/2 and
gRPC. The TCP handshake is emitted once per flow, payloads are replayed in
order with PSH/ACK flags, and `close()`/`shutdown()` calls produce FIN/ACK
teardowns when observed.

The feature is enabled by default. Use `--no-unix-to-tcp` to suppress UNIX
packets entirely and preserve the legacy behaviour, or `--unix-only` to emit
just the synthesised UNIX traffic. When UNIX TCP synthesis is active the PCAP
link-layer is forced to Ethernet (DLT_EN10MB) so both AF_UNIX and AF_INET
traffic can coexist in the same capture.

```console
py_strace2pcap.py --unix-only output.pcap < trace.log
```

Each stream uses source IPs in the `10.0.0.0/24` range and destination IPs in
`10.0.1.0/24`, with client ports derived from the inode number and a default
server port of 50051 to hint gRPC dissectors.

## Link-layer options

When UNIX TCP synthesis is enabled the converter always writes Ethernet
frames (DLT_EN10MB) so both UNIX and INET traffic share the same link-layer.
Disable the feature with `--no-unix-to-tcp` to regain the original behaviour,
where the default link-layer is `raw` (DLT_RAW) and `--linktype ether` opt-in
restores the Ethernet + 802.1Q encoding for classic AF_INET/AF_INET6 sockets.

```console
py_strace2pcap.py --no-unix-to-tcp --linktype ether capture.pcap < trace.log
```

TLS-encrypted payloads remain opaque because the plaintext is not available in
the strace logs.

# play with your pcap
read network traffic from strace with wireshark, tshark, or tcpdump
```console
wireshark file_to_store.pcap
```

# helpers
1) there is example straceSample in example directory, along with example straceSample.pcap

2) when protocol is not recognized in wireshark/tshark, do use decode packet on tcp payload (check screenshots in images directory)
or specify dissector in commandline while running tshark/wireshark
texample below is for mongo protocol
```console
wireshark ./example/straceSample.pcap  -d tcp.port==27017,mongo 
```
3) if program observed with strace logs too much operations, and file becomes too large 
try to add **-e trace=network** to strace command, to isolate just network traffic

4) strace data encodings in pcap:

* PID from strace file is encoded in eth.addr (src or dst depending on direction of a packet). PID is encoded as a decimal within hex/byte of ethernet mac, so for PID 123456 you should see mac address 00:00:00:12:34:56

* FD (file descriptor) from strace is encoded in vlan ID (802.1q), for example FD 17 is encoded as VlanID 17

* session (unique fd session, as same fd can be closed an opened more than once) is encoded in other eth.addr (src or dst, other than PID, depending on direction of a packet) at lower part of mac starting from eth.addr[5]

* system call is encoded along with session on eth.addr[1]
   * read = 1
   * write = 2
   * sendmsg = 3
   * recvmsg = 4
   * recvfrom = 5
   * sendto = 6

example filter for PID 654321 and FD 7 : eth.addr == 00:00:00:65:43:21 && vlan.id == 7

5) if you like to see old and familiar, default, strace output, there is a tool in tools directory that will convert -xx format to generic format
``` console
./tools/strace_convert/xx2generic.py < StraceOutFile_with_-xx > StraceOutFile_ascii_readable
```

6) if you want to have a single command for catching just observed pid or command pcap file do use script that wraps strace execution:
``` console
./strace2pcap.sh /tmp/sameFile.pcap "strace args"
```
for example:
``` console
./strace2pcap.sh /tmp/OUT2.pcap "curl http://www.google.com"
```
or:
``` console
./strace2pcap.sh /tmp/OUT2.pcap "-p some_pid_of_interest"
```
note: to run ./strace2pcap.sh you will need scapy python module installed

7) if you want to pipe pcap content to wireshark or tcpdump use:
``` console
./strace2pcap-pipe.sh /tmp/OUT2.pcap "curl http://www.github.com" | tcpdump -A -r -
```

8) wireshark can't show more than 256 bytes of some protocol payload, for that reason I've created cli tshark based renders, so one can take payload of a protocl (like es query, or statsd message) from recorder strace, ie converted pcap file. look at tools/cli_tshark_protocol_render

# reporting issues
please send strace command you've used and strace output

