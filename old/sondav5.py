#!/usr/bin/python
# -*- coding: utf-8 -*-

################################################################################
#                                                                              #
# sondav5.py                                                                   #
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
from collections import defaultdict
import MySQLdb as mdb
import sys
import datetime

# Declaración de variables globales
hosts   = defaultdict(list)                     # Diccionario de hosts {MAC, [IP, switch, port, state]}
details = ['srcip', 'switch', 'inport']   # Lista de información a obtener de un paquete recibido
n_packets = {}                                  # Almacena el numero de paquetes para cada host {MAC, Packets}
network_id = None                               # Variable global que almacena los parámetros de red

# Punteros de acceso al diccionario
IP      = 0
SWITCH  = 1
PORT    = 2
STATUS  = 3

# Constantes
REQUEST = 1
TIMER = 10
ip_controller = ('127.0.0.1')                   # No utilizada: Dirección localhost. Necesidad de migrar el controlador
ip1 = IPAddr('10.0.0.101')
ip2 = IPAddr('10.0.0.102')                      # Necesaria para pruebas hasta que se migre el controlador
ipRandom = IPAddr('1.2.3.4')
mac_origen_sw = EthAddr('ea:c3:da:17:25:42')
mac_origen_h2 = EthAddr('02:fd:00:05:01:01')    # Necesaria para pruebas hasta que se migre el controlador
mac_destino = EthAddr('ff:ff:ff:ff:ff:ff')      # ARP broadcast


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
        self.network = None

    def set_initial_state(self):
        """
        Función que realiza un query de la red y decide políticas en función del tráfico
        recibido, actualizando finalmente la Flow Table.
        """
        self.query = packets(1,['srcmac','srcip'])  # Query que detecta paquetes segun una política de match
        self.query.register_callback(self.learn_new_MAC)    # Registro del callback
        self.forward = self.flood   # Política por defecto: inundar la red
        self.update_policy()    # Actualizar políticas del switch

    def set_network(self,network):
        """
        Función que actualiza el estado de la red
        """
        self.network = network
        set_network_id(self.network)

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
        self.save(pkt)          # Guardar la información en la base de datos

    def save(self,pkt):
        """
        Función que comprueba si un host se encuentra en el diccionario.
        Si el host se encuentra en el diccionario, actualiza su estado a ON, ya que ha vuelto
        a conectarse a la red.
        En caso negativo, lo almacena en el diccionario y en la base de datos.
        """
        item = pkt['srcmac']    # Elemento que contiene la MAC del paquete
        if not item in hosts.keys():            # Si el elemento no esta en el diccionario,

            for detail in details:              # almacena la información relevante
                hosts[item].append(pkt[detail])
            
            hosts[item].append('on')

            self.store_db(pkt)                  # y lo guarda en la base de datos
            print('Nuevo host detectado: ' + str(item) + ' -- Guardado en DB')

        else:                                   # Si ya estaba en el diccionario,
            hosts[item][IP] = pkt['srcip']      # actualizar campos
            hosts[item][PORT] = pkt['inport']

    def store_db(self,pkt):
        """
        Función que recibe un paquete determinado y extrae los parámetros relevantes para
        guardarlos en la base de datos.
        """
        try:
            con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');   # Conexión con la base de datos
            cur = con.cursor()  # Creación del cursor
            
            # Creación de parámetros de la tabla
            state = 'on'
            mac_addr = str(pkt['srcmac'])
            ip_addr = str(pkt['srcip'])
            port = pkt['inport']
            time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            value = 'Medio'

            # Sentencia SQL
            sql = "INSERT INTO HOSTS(Estado, MAC, IP, Puerto, Hora, Importancia) \
                    VALUES ('%s', '%s', '%s', '%s', '%s', '%s')" \
                    % (state, mac_addr, ip_addr, port, time, value)

            # Ejecución de la sentencia y commit
            cur.execute(sql)
            con.commit()

        except mdb.Error, e:
            db.rollback()   # Rollback de la base de datos en caso de excepción

        finally:         
            if con:    
                con.close() # Cerrar la conexión

def get_network_id():
    return network_id

def set_network_id(network):
    global network_id
    network_id = network

def packet_count_register(counts):
    """
    Función que recibe los paquetes que ha contado el switch y los registra en 
    un diccionario asociado a la dirección MAC de cada host que actúa como contador.
    """

    print counts

    for host in hosts.keys():   # Recorrer el diccionario de hosts
        if(not host in n_packets.keys()):   # Si el host no se encuentra en el diccionario 
            n_packets[host] = 0             # se añade con el contador a 0
        
        # Creación de una política de match para comparar el origen de los paquetes
        m = match(srcmac=host)  

        # Lógica de tratamiento de los contadores de paquetes
        if(m in counts.keys()):   # Si la política se encuentra en el diccionario generado en el callback

            if(n_packets.get(host) < counts.get(m)):    # Si el contador es menor al registrado 
                print('El host con MAC ' +  str(host) + ' e IP ' + str(hosts.get(host)[IP]) + ' genera trafico')
                n_packets[host] = counts.get(m)         # actualizar el valor
                if(hosts[host][STATUS] == 'off'):
                    set_on(host)
                    hosts[host][STATUS] = 'on'
                    print('El host con MAC ' +  str(host) + ' e IP ' + str(hosts.get(host)[IP]) + ' estado ON')


            else:                                       # Si es menor o igual
                print('El host con MAC ' +  str(host) + ' e IP ' + str(hosts.get(host)[IP]) + ' no genera trafico')
                
                if(hosts[host][STATUS] == 'on'):

                    set_off(host)                           # poner el host a estado off
                    hosts[host][STATUS] = 'off'
                    
                    print('El host con MAC ' +  str(host) + ' e IP ' + str(hosts.get(host)[IP]) + ' estado OFF')

                    switch = hosts.get(host)[SWITCH]
                    port = hosts.get(host)[PORT]
                    arp_ipdest = hosts.get(host)[IP]

                    send_arp(REQUEST,get_network_id(),switch,port,ip2,mac_origen_sw,arp_ipdest,mac_destino)
                    print('ARP enviado al host con IP '+ str(hosts.get(host)[IP]))


def set_on(host):
    """
    Función que actualiza en la base de datos el estado de un host a ON
    """
    try:
        con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');

        cur = con.cursor()

        state = 'on'
        mac_addr = str(host)
        ip_addr = str(hosts.get(host)[IP])
        port = hosts.get(host)[PORT]
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        

        sql = "UPDATE HOSTS SET Estado = '%s', IP = '%s', Puerto = '%d', Hora = '%s' \
            WHERE MAC = '%s'" \
            % (state, ip_addr, port, time, mac_addr)
        
        cur.execute(sql)
        con.commit()

    except mdb.Error, e:
        db.rollback()

    finally:
        if con:
            con.close()

def set_off(host):
    """
    Función que actualiza en la base de datos el estado de un host a OFF
    """
    try:
        con = mdb.connect('localhost', 'root', 'mysqlpass', 'sonda');   # Conexión con la base de datos

        cur = con.cursor()  # Creación del cursor

        # Creación de parámetros
        state = 'off'
        mac_addr = str(host)
        # ip_addr = hosts.get[host]
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sentencia SQL
        sql = "UPDATE HOSTS SET Estado = '%s', Hora = '%s' \
                WHERE MAC = '%s'" \
                % (state, time, mac_addr)

        # Ejecución de la sentencia y commit
        cur.execute(sql)
        con.commit()

    except mdb.Error, e:
        db.rollback()   # Rollback de la base de datos en caso de excepción

    finally:         
        if con:    
            con.close() # Cierra la conexión

def packet_counts():
    """
    Función que cuenta los paquetes recibidos por el switch mediante un query
    y llama a un callback cada 10 segundos que se encargará de aplicar lógica 
    a la información recibida. 
    """
    q = count_packets(TIMER,['srcmac'])    # Query que cuenta los paquetes segun la MAC origen    
    q.register_callback(packet_count_register)  # Callback llamado cada 10 segundos
    return q


def send_arp(msg_type,network,switch,outport,srcip,srcmac,dstip,dstmac):
        """
        Función que construye un paquete ARP y lo inyecta en la red
        """
        arp = Packet()
        arp = arp.modify(protocol=msg_type)
        arp = arp.modify(ethtype=ARP_TYPE)
        arp = arp.modify(switch=switch)
        arp = arp.modify(inport=-1)
        arp = arp.modify(outport=outport)
        arp = arp.modify(srcip=srcip)
        arp = arp.modify(srcmac=srcmac)
        arp = arp.modify(dstip=dstip)
        arp = arp.modify(dstmac=dstmac)
        arp = arp.modify(raw='')

        network.inject_packet(arp)


def main():
    """
    Función principal que es llamada a la hora de ejecutar el módulo de la sonda
    con Pyretic.
    """
    return (packet_counts() +
            probe())
