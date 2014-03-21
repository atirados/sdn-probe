
################################################################################
#                                                                              #
# sondav1.py                                                                   #
# Author: Adrian Tirados                                                       #
#                                                                              #
################################################################################
#                                                                              #
# Sonda de deteccion automatica de dispositivos en red.                        #
#                                                                              #
#    La sonda es un controlador remoto de un switch basado en Open vSwitch,    #
# un switch virtual con soporte de OpenFlow. Dicho controlador esta            #
# implementado en Pyretic, un Northbound API sobre POX. Los elementos del      #
# escenario de la red se encuentran virtualizados mediante vnx.                #
#                                                                              #
#    Funcionamiento: El controlador actua como un switch con autoaprendizaje,  #
# de manera que construye de manera dinamica sus politicas de red y las        #
# registra en las Flow Tables. Por otra parte, cuenta con la funcionalidad     #
# de almacenar en una base de datos a tiempo real los diferentes hosts que     #
# se conectan a la red. Con cada nueva conexion, el controlador almacena en    #
# la DB mediante API MySQLdb los siguientes valores:                           #
#    - Estado de la maquina                                                    #
#    - Direccion MAC                                                           #
#    - Direccion IP                                                            #
#    - Puerto de entrada                                                       #
#    - Hora de conexion/desconexion                                            #
#    - Importancia del activo                                                  #
#                                                                              #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
import MySQLdb as mdb
import sys
import datetime

hosts = []  # Variable global que almacena los hosts que se conectan
n_packets = {}

class mac_learner(DynamicPolicy):
    """Standard MAC-learning logic"""
    def __init__(self):
        super(mac_learner,self).__init__()
        self.flood = flood()           # REUSE A SINGLE FLOOD INSTANCE
        self.set_initial_state()

    def set_initial_state(self):
        self.query = packets(1,['srcmac','switch'])
        self.query.register_callback(self.learn_new_MAC)
        self.forward = self.flood  # REUSE A SINGLE FLOOD INSTANCE
        self.update_policy()

    def set_network(self,network):
        self.set_initial_state()

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query

    def learn_new_MAC(self,pkt):
        """Update forward policy based on newly seen (mac,port)"""
        self.forward = if_(match(dstmac=pkt['srcmac'],
                                switch=pkt['switch']),
                          fwd(pkt['inport']),
                          self.forward) 
        self.update_policy()
        self.save(pkt)

    def save(self,pkt):
        """Comprueba si el host se encuentra en la lista, y en caso negativo, lo almacena"""
        item = pkt['srcmac']
        if not item in hosts:
            hosts.append(item)
            self.store_db(pkt)
            print('Nuevo host detectado: ' + str(item) + ' -- Guardado en DB')

    def store_db(self,pkt):
        """Cuando hay un host nuevo en la red, guarda sus parametros en la base de datos"""
        try:
            con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');

            cur = con.cursor()

            cur.execute("SELECT * FROM HOSTS")
            
            state = 'on'
            mac_addr = str(pkt['srcmac'])
            ip_addr = str(pkt['srcip'])
            port = pkt['inport']
            time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            value = 'Medio'

            sql = "INSERT INTO HOSTS(Estado, MAC, IP, Puerto, Hora, Importancia) \
                    VALUES ('%s', '%s', '%s', '%d', '%s', '%s')" \
                    % (state, mac_addr, ip_addr, port, time, value)

            cur.execute(sql)
            con.commit()

        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            sys.exit(1)

        finally:         
            if con:    
                con.close()

def packet_count_register(counts):
    print "----counts------"
    print counts

    for host in hosts:
        if(not host in n_packets.keys()):
            n_packets[host] = 0
        
        m = match(srcmac=host)

        if(m in counts.keys()):
            if(n_packets.get(host) < counts.get(m)):
                print('El host '+ str(host) + ' genera trafico')
                n_packets[host] = counts.get(m)
            else:
                print('El host ' +  str(host) + ' no genera trafico')
        else:
            print('El host ' +  str(host) + ' no genera trafico')


def packet_counts():
  q = count_packets(10,['srcmac'])
  q.register_callback(packet_count_register)
  return q
        
def main():
    return (packet_counts() +
            mac_learner())