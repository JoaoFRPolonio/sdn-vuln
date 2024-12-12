#!/usr/bin/env python
import json
import nmap

def run(ip_range):
  nm = nmap.PortScanner()
  scan_range = nm.scan(hosts=ip_range, arguments='-sP -PR')
  result = scan_range['scan']
  print(result)
  return result

def alive_hosts(ip_range):
  ip_addresses = list(run(ip_range).keys())
  print(ip_addresses)
  return ip_addresses
