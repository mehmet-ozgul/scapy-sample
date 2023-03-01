# Scapy Sample

Scapy is a python library and a repr harness that allows packet manipulation. 
It works both live interfaces and stored packets. 
For mor information see [scapy](https://github.com/secdev/scapy).

This is a sample project to demonstrate how to use scapy to read, alter and re-write pcap files. 

- Reads the input file
- Filters by src and dst ports and tries to parse matching packets as RTP
- When the sequence IDs are found, alters the timestamps and sets the mark bit 
- Writes packets to the output file