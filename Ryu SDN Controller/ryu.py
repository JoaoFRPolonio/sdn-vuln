# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
#sys.path.append('/usr/lib/python3.10/site-packages')

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, ipv6, udp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu.controller import dpset

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from operator import attrgetter

import dpkt
import socket
import json
import time
import datetime
import pickle
#import pdb
import random

import networkx as nx
import paramiko

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from webob import Response

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/mactable/{dpid}'

port_to_vlan = {1: 10, 2: 10, 3: 20, 4: 20, 5: 20, 6: 10, 7: 20, 8: 10, 9: 10, 10: 20, 11: 10}
mac_to_switch = {}
ip_to_switch_port = {}
datapaths = []


class cont_of13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(cont_of13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        hub.spawn(self.myfunction)
        self.net = nx.DiGraph()
        self.cnt = 0
        self.cnt1 = 0
        self.sws = []
        self.links = []
        self.hosts = []
        self.wait = False
        self.INTERVAL = 2
        wsgi = kwargs['wsgi']
        wsgi.register(MySwitch_Cont_Controller, {simple_switch_instance_name: self})
        #self.ndpi_classifier = NDPI()
        

    def myfunction(self):
       while True:
         try:
           hub.sleep(self.INTERVAL)
           if self.cnt1 > 15 * ( 1 / self.INTERVAL):
              if self.cnt % 2 == 0:
                 self.get_sws_links_hosts()
                 # measuring control channel delay between controller and switch
                 # to measure this we use rtt of request-reply switch statistics
                 # we also update the link costs
                 for switch in self.sws:
                    self._request_stats(switch[0])

              if self.cnt % 2 == 1:
                 self.get_topology_data(None)

              if not self.wait:
                 #if not self.path_test:
                 # I can increment the counter only if the controller is not waiting
                 # for a delay test conclusion
                 self.cnt = self.cnt + 1
              else:
                 # waiting for controller obtaining the complete topology
                 self.get_sws_links_hosts()

           if self.cnt1 < 15 * ( 1 / self.INTERVAL) + 1:
              self.cnt1 = self.cnt1 + 1

         except KeyboardInterrupt:
          print ("Closing ....")
          pass

    def get_sws_links_hosts (self):
        switch_list = get_switch(self.topology_api_app, None)
        self.sws = [(switch.dp, switch.dp.id) for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        self.links = [(link.src.dpid, link.dst.dpid, link.src.port_no) for link in links_list]
        host_list = get_host(self.topology_api_app, None)
        self.hosts = [(host.mac, host.port.dpid, host.port.port_no) if host.mac < '00:00:00:00:00:ff' else '' for host in host_list]
        self.hosts = list(filter(lambda x: x != "", self.hosts))

    #@set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        nodes = []
        rows = []
        for switch in self.sws:
           nodes.append(switch[1])
           row = []
           row.append(switch[1])
           for link in self.links:
              if link[0] == switch[1]:
                  row.append(link[1])
           for host in self.hosts:
              if host[1] == switch[1]:
                  row.append(host[0])
           rows.append(row)

        for host in self.hosts:
           nodes.append(host[0])
           row = []
           for switch in self.sws:
              if host[1] == switch[1]:
                  row.append(host[0])
                  row.append(host[1])
           rows.append(row)

        cs = []
        for n in nodes:
           for row in rows:
              if len(row) >= 1 and n == row[0]:
                 c = []
                 for n1 in nodes:
                    if n1 in row and n1 != row[0]: 
                       c.append(1)
                    else:
                       c.append(0)
                 cs.append(c)
                 break

        for host in self.hosts:
            self.net.add_edge(host[0], host[1], weight=1, port=1)
            self.net.add_edge(host[1], host[0], weight=1, port=host[2])

        for link in self.links:
            if link[0] in self.delay and link[2] in self.delay[link[0]]:
               cost = int(1000.0 * self.delay[link[0]][link[2]])
               self.net.add_edge(link[0], link[1], weight=cost, port=link[2])
            else:
               self.net.add_edge(link[0], link[1], weight=1, port=link[2])

    def proactive_flow_rule_install (self, dp, dpid, src_mac, dst_mac):
        self.logger.info("<==== Entering inside proactive_flow_rule_install() ")

        self.mac_to_port.setdefault(dpid, {})

        datapath = None
        parser = None
        datapath = dp
        parser = datapath.ofproto_parser
        if datapath == None:
            # Nothing to do here!
            return

        # get correct in_port of the prev node
        path_selected = self.path_list[self.selected_action]
        index_current_dpid = path_selected.index(dpid)
        prev_node = path_selected [index_current_dpid - 1]
        in_port = self.net[dpid][prev_node]['port']

        # get correct out_port of the next node
        next_node = path_selected [index_current_dpid + 1]

        out_port = self.net[dpid][next_node]['port']

        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
        actions = [parser.OFPActionOutput(out_port)]
        self.logger.info("Proactive rule in switch %s: (%s, %s)", dpid, match, actions)
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch(in_port=out_port, eth_dst=src_mac, eth_src=dst_mac)
        actions = [parser.OFPActionOutput(in_port)]
        self.logger.info("Proactive rule in switch %s: (%s, %s)", dpid, match, actions)
        self.add_flow(datapath, 1, match, actions)

        # insert new entries in self.mac_to_port
        self.mac_to_port[dpid][src_mac] = in_port
        self.mac_to_port[dpid][dst_mac] = out_port

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flows(self, datapath, src_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_port)
        mod = parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)

        match = parser.OFPMatch(out_port=src_port)
        mod = parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        req = parser.OFPFlowStatsRequest(datapath, 0, ofproto.OFPTT_ALL, ofproto.OFPP_ANY, ofproto.OFPG_ANY, 0, 0, match)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        curr_time = time.time_ns() / (10 ** 9)
        historical_time = 0
        prev_time = 0
        for stat in ev.msg.body:
            print("port_statistics", stat.port_no,stat.rx_packets)

    # for getting flow stats
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid_rec = ev.msg.datapath.id
        for statistic in ev.msg.body:
            if 'eth_src' in statistic.match and 'eth_dst' in statistic.match:
                print("flow_statistics",statistic.match['eth_src'])
                print("flow_statistics",statistic.match['eth_dst'])

    def process_classification_result(self, classification_result):
        app_protocol = classification_result.app_protocol
        category = classification_result.category
        confidence = classification_result.confidence
    
        if app_protocol != PROTOCOL_UNKNOWN:
            # Flow is classified
            protocol_name = self.ndpi_classifier.protocol_name(app_protocol)
            category_name = self.ndpi_classifier.protocol_category_name(category)
            print("Flow classified as protocol: {}, category: {}, confidence: {}".format(protocol_name, category_name, confidence))
        
            # Take appropriate actions based on the classification result
            if category == CATEGORY_WEB:
                # Perform actions specific to web traffic
                pass
            elif category == CATEGORY_EMAIL:
                # Perform actions specific to email traffic
                pass
            # Add more categories and corresponding actions as needed
        
        else:
            # Flow classification failed
            print("Flow classification failed with confidence: {}".format(confidence))
        
            if confidence == CONFIDENCE_HIGH:
                # High confidence in the classification failure
                # Take actions for unclassified flows with high confidence
            
                # Example: Block the flow
                #self.block_flow()
                print('Block flow')
            
            elif confidence == CONFIDENCE_MEDIUM:
                # Medium confidence in the classification failure
                # Take actions for unclassified flows with medium confidence
            
                # Example: Log the flow for further analysis
                #self.log_flow()
                print('Log flow')
            
            else:
                # Low confidence in the classification failure
                # Take actions for unclassified flows with low confidence
            
                # Example: Allow the flow and continue monitoring
                #self.continue_monitoring_flow()
                print('Allow flow')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        if datapath not in datapaths:
            datapaths.append(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_header = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # mapeamento IP-Switch-Port
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = ip_header

        # Extract IP address and port information
        src_ip = ip_pkt.src if ip_pkt else None
        src_port = in_port

        # Extract source MAC address to determine the associated switch
        src_mac = eth_pkt.src

        # Identify the switch associated with the source MAC address
        switch_id = dpid

        # Perform processing or actions based on IP address, port, and switch information
        self.logger.info("Packet received from switch %s. Source IP: %s, Source Port: %s",
                         switch_id, src_ip, src_port)

        # Store the data in the dictionary with src_ip as the key
        ip_to_switch_port[src_ip] = {'switch_id': switch_id, 'src_port': src_port}
        print(ip_to_switch_port)

        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            if port_to_vlan[in_port] != port_to_vlan[out_port]:
                actions = []

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

class MySwitch_Cont_Controller(ControllerBase):
    def __init__(self, req, link, data, **config):
      super(MySwitch_Cont_Controller, self).__init__(req, link, data, **config)
      self.simple_switch_app = data[simple_switch_instance_name]

    @route('simpleswitch', url, methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):
      simple_switch = self.simple_switch_app
      dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

      #pdb.set_trace()

      if dpid not in simple_switch.mac_to_port_1:
        return Response(status=404)

      mac_table = simple_switch.mac_to_port_1.get(dpid, {})
      body = json.dumps(mac_table).encode("utf-8")
      return Response(content_type='application/json', body=body)

    def get_datapath_by_switch_id(self, switch_id):
      for datapath in datapaths:
          if datapath.id == switch_id:
                return datapath
      return None
    
    def execute_ssh_command(self, hostname, username, password, command):
      client = paramiko.SSHClient()
      client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      client.connect(hostname, username=username, password=password, look_for_keys=False)
    
      # Enable PTY allocation
      channel = client.get_transport().open_session()
      channel.get_pty()
    
      # Execute the command
      channel.exec_command('ls -l')
    
      # Retrieve command output
      output = channel.makefile().read()
      errors = channel.makefile_stderr().read()
    
      print("Command output:")
      print(output)
    
      if errors:
          print("Error message:")
          print(errors)
    
      channel.close()
      client.close()



    def addd_flow(self, datapath, priority, match, actions, buffer_id=None):
      ofproto = datapath.ofproto
      parser = datapath.ofproto_parser
      inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
      if buffer_id:
          mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
      else:
          mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
      datapath.send_msg(mod)

    #def clean_flow_rules(self, switch_id, src_port):
      #datapath = self.get_datapath_by_switch_id(switch_id)
     # datapath = switch_id
     # ofproto = datapath.ofproto
     # parser = datapath.ofproto_parser

      # Construct the flow deletion message for the specific source port
     # match = parser.OFPMatch(in_port=src_port)
     # mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
     #                           out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
     #                           match=match)
     # datapath.send_msg(mod)

    def clean_flows(self, switch_id, src_port):
       datapath = self.get_datapath_by_switch_id(switch_id)
       ofproto = datapath.ofproto
       parser = datapath.ofproto_parser
       print("#################"+str(src_port))
       #match = parser.OFPMatch(in_port=src_port)
       #mod = parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
       #datapath.send_msg(mod)
       # Delete all flow rules except priority=0, actions=CONTROLLER
       match = parser.OFPMatch()
       actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
       priority = 0

       # Construct the flow deletion message
       mod = parser.OFPFlowMod(
           datapath=datapath,
           command=ofproto.OFPFC_DELETE,
           out_port=ofproto.OFPP_ANY,
           out_group=ofproto.OFPG_ANY,
           match=match,
           priority=priority,
           instructions=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
       )

       # Send the flow deletion message
       datapath.send_msg(mod)

       # install table-miss flow entry
       match = parser.OFPMatch()
       actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
       self.addd_flow(datapath, 0, match, actions)

    @route('simpleswitch','/simpleswitch/change_vlan/{ip_address}/{vlan_id}', methods=['GET'])
    def change_vlan(self, req, **kwargs):
      simple_switch = self.simple_switch_app
      # Retrieve the switch ID and source port from ip_data
      print("ENTREI")
      print(kwargs['ip_address'])
      print(kwargs['vlan_id'])
      ip_address = kwargs['ip_address']
      vlan_id = int(kwargs['vlan_id'])
      if ip_address in ip_to_switch_port:
          switch_id = ip_to_switch_port[ip_address]['switch_id']
          print(switch_id)
          src_port = ip_to_switch_port[ip_address]['src_port']
          print(src_port)
          # Create the match conditions
          datapath = self.get_datapath_by_switch_id(switch_id)
          ofproto = datapath.ofproto
          parser = datapath.ofproto_parser
          match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)

          # Create the actions (allow communication with gateway only)
          actions = [parser.OFPActionSetField(ipv4_dst='192.168.14.6'),
                   parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

          # Set the priority of the flow rule
          priority = 100

          # Install the flow rule
          self.addd_flow(datapath, priority, match, actions)
      else:
          print("IP address not found in ip_data: ", ip_address)
          return Response(status=404)

      #self.execute_ssh_command('192.168.13.162', 'catalyst', 'catalyst', 'sudo ifconfig ens33 192.168.14.81 netmask 255.255.255.0')

      # Update the VLAN ID for the source port in port_to_vlan
      port_to_vlan[src_port] = vlan_id
      print(port_to_vlan)

      # Clean all flow rules associated with the source port
      self.clean_flows(switch_id, src_port)

      #self.execute_ssh_command('192.168.14.81', 'catalyst', 'catalyst', 'sudo dhclient ens33')

      body = json.dumps(port_to_vlan).encode("utf-8")
      return Response(content_type='application/json', body=body)
