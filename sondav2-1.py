#!/usr/bin/python
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
# sondav2.py                                                                   #
# Author: Adrián Tirados                                                       #
#                                                                              #
################################################################################
#                                                                              #
# Sonda de detección automática de dispositivos en red.                        #
#                                                                              #
#    La sonda es un controlador remoto de un switch basado en Open vSwitch,    #
# un switch virtual con soporte de OpenFlow. Dicho controlador está            #
# implementado en Pyretic, un Northbound API sobre POX. Los elementos del      #
# escenario de la red se encuentran virtualizados mediante vnx.                #
#                                                                              #
#    Funcionamiento: El controlador actúa como un switch con autoaprendizaje,  #
# de manera que construye de manera dinámica sus políticas de red y las        #
# registra en las Flow Tables. Por otra parte, cuenta con la funcionalidad     #
# de almacenar en una base de datos a tiempo real los diferentes hosts que     #
# se conectan a la red. Con cada nueva conexión, el controlador almacena en    #
# la DB mediante API MySQLdb los siguientes valores:                           #
#    - Estado de la máquina                                                    #
#    - Dirección MAC                                                           #
#    - Dirección IP                                                            #
#    - Puerto de entrada                                                       #
#    - Hora de conexión/desconexión                                            #
#    - Importancia del activo                                                  #
#                                                                              #
#   Cuando tiene lugar una desconexión, el controlador registra este evento    #
# en la base de datos, actualizando el estado de la máquina y la hora del      #
# suceso.                                                                      #
#                                                                              #
#   Adicionalmente, el switch es sensible a movilidad entre subredes,          #
# registrando de igual manera estas circunstancias.                            #
#                                                                              #
################################################################################


# Importar dependencias

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
import MySQLdb as mdb
import sys
import datetime

# Declaración de variables globales

hosts = {}  # Almacena los hosts que se conectan {MAC, IP}
n_packets = {}  # Almacena el numero de paquetes para cada host {MAC, Packets}

class probe(DynamicPolicy):
    """
    Clase que describe un switch con capacidad de autoaprendizaje. Adicionalmente, cuenta con
    funciones que detectan la conexión y desconexión de hosts, guardando dinámicamente la 
    información en una base de datos remota.
    """
    def __init__(self):
        """
        Función preliminar que actúa como constructor.
        """
        super(probe,self).__init__()
        self.flood = flood()    # Política flood() predefinida en pyretic. Inunda la red mediante un STP    
        self.set_initial_state()    # Programar el switch a su estado inicial

    def set_initial_state(self):
        """
        Función que realiza un query de la red y decide políticas en función del tráfico
        recibido, actualizando finalmente la Flow Table.
        """
        self.query = packets(None,['srcmac','switch'])  # Query que detecta paquetes segun una política de match
        self.query.register_callback(self.learn_new_MAC)    # Registro del callback
        self.forward = self.flood   # Política por defecto: inundar la red
        self.update_policy()    # Actualizar políticas del switch

    def set_network(self,network):
        """
        Función que actualiza el estado de la red
        """
        self.set_initial_state()

    def update_policy(self):
        """
        Función que actualiza las políticas del switch basado en el valor de la política 
        forward y las políticas de la query.
        """
        self.policy = self.forward + self.query     # Composición paralela de políticas

    def learn_new_MAC(self,pkt):
        """
        Función que actualiza la política forward basada en la detección de una nueva
        dirección MAC en un paquete que recibe el switch en un puerto determinado.
        """
        self.forward = if_(match(dstmac=pkt['srcmac'],  # En función de las políticas de match,
                                switch=pkt['switch']),  # el switch es capaz de reenviar el paquete
                          fwd(pkt['inport']),           # por el puerto origen, creando una nueva política
                          self.forward)                 # En caso contrario, se ejecuta la política forward
        self.update_policy()    # Actualizar la políticas del switch
        self.save(pkt)      # Guardar la información en la base de datos

    def save(self,pkt):
        """Comprueba si el host se encuentra en la lista, y en caso negativo, lo almacena"""
        item = pkt['srcmac']
        if not item in hosts.keys():
            hosts[item] = str(pkt['srcip'])
            self.store_db(pkt)
            print('Nuevo host detectado: ' + str(item) + ' -- Guardado en DB')
        else:
            self.set_on(pkt)
            print('Host ' +  str(item) + ' -- Actualizado a ON')

    def store_db(self,pkt):
        """Cuando hay un host nuevo en la red, guarda sus parametros en la base de datos"""
        try:
            con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');

            cur = con.cursor()
            
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
            db.rollback()

        finally:         
            if con:    
                con.close()

    def set_on(self,pkt):  # No funciona (???)
        """Actualiza el estado de un host a ON"""
        try:
            con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');

            cur = con.cursor()
            
            state = 'on'
            mac_addr = str(pkt['srcmac'])
            ip_addr = str(pkt['srcip'])
            port = pkt['inport']
            time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            value = 'Medio'

            sql = "UPDATE HOSTS SET Estado = '%s' \
                    WHERE MAC = '%s'" \
                    % (state, mac_addr)

            cur.execute(sql)
            con.commit()

        except mdb.Error, e:
            db.rollback()

        finally:         
            if con:    
                con.close() 



def packet_count_register(counts):
    print "----counts------"
    print counts

    for host in hosts.keys():
        if(not host in n_packets.keys()):
            n_packets[host] = 0
        
        m = match(srcmac=host)

        if(m in counts.keys()):
            if(n_packets.get(host) < counts.get(m)):
                print('El host con MAC ' +  str(host) + ' e IP ' + hosts.get(host) + ' genera trafico')
                n_packets[host] = counts.get(m)
            else:
                print('El host con MAC ' +  str(host) + ' e IP ' + hosts.get(host) +' no genera trafico')
                set_off(host)
                print('El host con MAC ' +  str(host) + ' e IP ' + hosts.get(host) +' estado OFF')
        else:
            print('El host con MAC ' +  str(host) + ' e IP ' + hosts.get(host) +' no genera trafico')

def set_off(host):
    """Actualiza el estado de un host a OFF"""
    try:
        con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');

        cur = con.cursor()
        
        state = 'off'
        mac_addr = str(host)
        # ip_addr = hosts.get[host]
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sql = "UPDATE HOSTS SET Estado = '%s', Hora = '%s' \
                WHERE MAC = '%s'" \
                % (state, time, mac_addr)

        cur.execute(sql)
        con.commit()

    except mdb.Error, e:
        db.rollback()

    finally:         
        if con:    
            con.close() 

def packet_counts():
  q = count_packets(10,['srcmac'])
  q.register_callback(packet_count_register)
  return q
        
def main():
    return (packet_counts() +
            probe())