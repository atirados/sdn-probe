
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet:  mininet.sh --topo linear,3 (or other single subnet)                #
# test:     start xterms - e.g., 'xterm h1 h2 h3' in mininet console           #
#           start tcpdump:  in each xterm,                                     #
#           IF=`ifconfig | head -n 1 | awk '{print $1}'`;                      #
#           tcpdump -XX -vvv -t -n -i $IF not ether proto 0x88cc > $IF.dump    #
#           h1 ping -c 2 h3                                                    #
#           examine dumps, confirm that h2 does not see packets on second ping #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
import time


ip_controller = ('127.0.0.1')
ip1 = IPAddr('10.0.0.101')
ip2 = IPAddr('10.0.0.102')
mac_origen_sw = EthAddr('ee:f3:48:30:cf:4f')
mac_origen_h2 = EthAddr('02:fd:00:05:01:01')
mac_destino = EthAddr('ff:ff:ff:ff:ff:ff')

class mac_learner(DynamicPolicy):
    """Standard MAC-learning logic"""
    def __init__(self):
        super(mac_learner,self).__init__()
        self.flood = flood()           # REUSE A SINGLE FLOOD INSTANCE
        self.set_initial_state()
        self.network = None

    def set_initial_state(self):
        self.query = packets(1,['srcmac','switch'])
        self.query.register_callback(self.learn_new_MAC)
        self.forward = self.flood  # REUSE A SINGLE FLOOD INSTANCE
        self.update_policy()
        


    def set_network(self,network):
        self.network = network

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query

    def send_arp(self,msg_type,network,switch,outport,srcip,srcmac,dstip,dstmac):
        """Construct an arp packet from scratch and send"""
        rp = Packet()
        rp = rp.modify(protocol=msg_type)
        rp = rp.modify(ethtype=ARP_TYPE)
        rp = rp.modify(switch=switch)
        rp = rp.modify(inport=-1)
        rp = rp.modify(outport=outport)
        rp = rp.modify(srcip=srcip)
        rp = rp.modify(srcmac=srcmac)
        rp = rp.modify(dstip=dstip)
        rp = rp.modify(dstmac=dstmac)
        rp = rp.modify(raw='')

        network.inject_packet(rp)


    def learn_new_MAC(self,pkt):
        """Update forward policy based on newly seen (mac,port)"""
        self.forward = if_(match(dstmac=pkt['srcmac']),
                          fwd(pkt['inport']),
                          self.forward) 
        self.update_policy()
        #print self.network

        inport = pkt['inport']
        srcip  = pkt['srcip']
        # srcmac = pkt['srcmac']
        dstip  = pkt['dstip']
        dstmac = pkt['dstmac']
        switch = pkt['switch']

        for i in range(10):
            self.send_arp(1,self.network,switch,1,ip2,mac_origen_h2,ip1,mac_destino)
            print 'ARP ENVIADO'
            time.sleep(1)


def main():
    return mac_learner()
