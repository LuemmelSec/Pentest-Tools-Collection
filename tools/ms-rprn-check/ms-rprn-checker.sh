#!/bin/bash

#Check a list for Servers (IPs oder DNS-Names) for MS-RPRN RPC vulnerability
#Needs impackets rpcdumpy.py in the same folder
#Needs python3
#The file with systems needs one entry per line

#Usage: ./script.sh -d DOMAIN -u USERNAME -p PASSWORD -f FILE
#Example: ./script.sh -d acme -u peter -p Start@123 -f /tmp/hosts.txt

while getopts d:u:p:f: flag
do
    case "${flag}" in
        d) domain=${OPTARG};;
        u) username=${OPTARG};;
        p) password=${OPTARG};;
        f) file=${OPTARG};;
    esac
done

while read p; do
  echo "testing $p"
  a="$domain"'/'"$username"':'"$password"'@'"$p"
  python3 rpcdump.py $a | grep 12345678-1234-ABCD-EF00-0123456789AB
done <$file
