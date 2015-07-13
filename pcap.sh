#!/bin/bash
usage() {
  echo "Usage:./$0 <pcap file>"
  echo "-s  <pcapfile>					Pcap file analysis"
  echo "-p  <inpcapfile> <outpcapfile> <configfile>	rewrite source/destination IP address"
  echo "-m  <inpcapfile> <outpcapfile> <configfile>	rewrite source/destination MAC address"
  exit
}

list_ip_conversation() {
  echo -e "\e[33mList of IPs conversation\e[0m"
  echo -e "\e[33m------------------------\e[0m"
  tshark -nn -r $1 -T fields -e ip.dst -e ip.src | sort | uniq
  if [ $? -ne 0 ]
  then
    echo "\e[36mPlease make sure Tshark is installed before using this script.\e[0m"
    exit 1
  fi
}

total_ip_frames() {
  echo -e "\e[33mTotal IP frames per conversation\e[0m"
  echo -e "\e[33m--------------------------------\e[0m"
  tshark -nn -r $1 -T fields -e ip.dst -e ip.src | sort | uniq -c | sed 's/^[ \t]*//'
  if [ $? -ne 0 ]
  then
    echo "\e[36mPlease make sure Tshark is installed before using this script.\e[0m"
    exit 1
  fi
}

list_ip() {
  echo -e "\e[33mList of IPs available in $1\e[0m"
  echo -e "\e[33m---------------------------\e[0m"
  tshark -nn -r $1 -T fields -e ip.src | sort | uniq | sed 's/$/,/g'
  if [ $? -ne 0 ]
  then
    echo "\e[36mPlease make sure Tshark is installed before using this script.\e[0m"
    exit 1
  fi
}

tcpip() {
cat << END > tcpip.py
#!/usr/bin/python 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

pkts = rdpcap("$1")

file = open("$3", "r")

d = {}

for i in file:
  k, v = i.strip().split(',')
  d[k.strip()] = v.strip()

for k, v in d.items():
  x = k
  y = v
  if len(y) is 0:
    y = k
  for p in pkts:
    if p.haslayer(TCP): 	# Proto options 
      if p[IP].src == x:
	p[IP].src = y
      if p[IP].dst == x:
	p[IP].dst = y

wrpcap("$2", pkts)
END
}

tcpmac() {
cat << END > tcpmac.py
#!/usr/bin/python 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

pkts = rdpcap("$1")

file = open("$3", "r")

d = {}

for i in file:
  k, v = i.strip().split(',')
  d[k.strip()] = v.strip()

for k, v in d.items():
  x = k
  y = v
  if len(y) is 0:
    y = k
  for p in pkts:
    if p.haslayer(Ether):  # Proto options 
      if p[Ether].src == x:
	p[Ether].src = y
      if p[Ether].dst == x:
	p[Ether].dst = y

wrpcap("$2", pkts)
END
}

rewrite_ip() {
  echo -e "\e[33mRewriting IP address in $1\e[0m"
  echo -e "\e[33m--------------------------\e[0m"
  #tcprewrite --infile=.tcpout --outfile=$2 --srcipmap=0.0.0.0/0:$3 --dstipmap=0.0.0.0/0:$4
  tcpip $1 $2 $3; python tcpip.py; rm tcpip.py
  if [ $? -ne 0 ]
  then
    echo "\e[36mPlease make sure python and python-scapy is installed before using this script.\e[0m"
    exit 1
  fi
  echo -e "\e[34mIP address written in $2\e[0m"

}

rewrite_mac() {
  echo -e "\e[33mRewriting MAC address in $1\e[0m"
  echo -e "\e[33m---------------------------\e[0m"
  #tcprewrite --infile=.tcpout --outfile=$2 --enet-smac=$3 --enet=dmac=$4
  tcpmac $1 $2 $3; python tcpmac.py; rm tcpmac.py
  if [ $? -ne 0 ]
  then
    echo "\e[36mPlease make sure python and python-scapy is installed before using this script.\e[0m"
    exit 1
  fi
  echo -e "\e[34mMAC address written in $2\e[0m"
}

if [ -z $1 ]
then
  usage
fi

while getopts spmo opts; do
  case $opts in
    s)
      list_ip_conversation $2
      echo `date` >> config.file
      echo "===================================" >> config.file
      #list_ip_conversation $2 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" >> config.file
      #echo >> config.file
      echo
      total_ip_frames $2
      #total_ip_frames $2 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" >> config.file
      #echo >> config.file
      echo 
      list_ip $2
      #list_ip $2 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" >> config.file
      #echo >> config.file
      tshark -nn -r $2 -T fields -e ip.src | sort | uniq | sed 's/$/,/g' > config.file
      echo
      echo "File created as config.file"
      #echo "##########################################################" >> config.file
      ;;
    p)
      rewrite_ip $2 $3 $4 $5
      echo
      ;;
    m)
      rewrite_mac $2 $3 $4 $5
      echo
      ;;
    \?)
      usage
      ;;
  esac
done
