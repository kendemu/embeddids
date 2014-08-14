Embedd IDS v0.1
=========
This is an IDS for embedding systems like raspberry pi : blocking attacks with censoring networks with arp spoofing. 
We did a test drive in raspberry pi.

sources-used
 pkt-tools v1.6
 http://kozos.jp/software/pkttools.html

System:
  ARP spoofing
  
  
  
                                |----------------|
                                |  Raspberry pi  |
                                |----------------|     
                                        |
                                        |
                                        |
                                        |
                                        |
  |---------|   send packets→           |                              |-----------|
  |hacker PC| ---------------------------------------------------------| target PC |
  |---------|                                                          |-----------|
  
Features :
  Cutting down ssh connections and https encrypted connections in order to find footprints of the hacker's computer
  
Warning:
 I can't take any responsibility if you used this IDS in cyber attacking.
 Don't use the pkt-change command! The IDS will ARP Storm and ICMP Strom your network!
