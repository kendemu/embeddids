while :
do
sudo ./pkt-send -i eth0 < ~/embeddids/spoof/arp-reply.txt
sudo ./pkt-send -i eth0 < ~/embeddids/spoof/arp-reply2.txt
sleep 1
done