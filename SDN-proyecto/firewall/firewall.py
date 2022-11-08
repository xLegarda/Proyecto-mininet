from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.addresses import IPAddr, EthAddr
import time
import csv

log = core.getLogger()

_flood_delay = 0

class Firewall(object):
  def __init__ (self, connection, transparent):
    self.connection = connection
    self.transparent = transparent

    # nuestra tabla
    self.macToPort = {}

    # nuestra tabla del firewall
    self.firewall = {}

    # agregas un par de reglas estaticas de entradas
    # Dos tipos de reglas: (srcip,dstip) o (dstip,dstport)
    with open('firewall-policies.csv', mode='r') as csv_file:
      csv_reader = csv.DictReader(csv_file)
      for row in csv_reader:
        m = 0
        sip = 0
        dip = 0
        if(row['mac']!='0'):
          m=EthAddr(row['mac'])
        if(row['srcip']!='0'):
          sip= IPAddr(row['srcip'])
        if(row['dstip']!='0'):
          dip= IPAddr(row['dstip'])
        self.AddRule(dpid_to_str(connection.dpid),m, sip, dip, int(row['dstport']))

    # Para escuchar los paquetes los incluimos a la conexion
    connection.addListeners(self)

    # Solo usamos esto para saber cuándo registrar un mensaje útil
    self.hold_down_expired = _flood_delay == 0

  def AddRule (self, dpidstr, macstr, srcipstr, dstipstr, dstport,value=True):
      if srcipstr == 0 and dstipstr == 0:
        self.firewall[(dpidstr,macstr)] = True
        log.debug("agregando L2-firewall regla de Src(%s) en %s", macstr, dpidstr)
      elif dstport == 0:
        self.firewall[(dpidstr,srcipstr,dstipstr)] = True
        log.debug("agregando L3-firewall regla de %s -> %s en %s", srcipstr, dstipstr, dpidstr)
      elif srcipstr == 0:
        self.firewall[(dpidstr,dstipstr,dstport)] = True
        log.debug("agregando L4-firewall regla de Dst(%s,%s) en %s", dstipstr, dstport, dpidstr)
      else:
        self.firewall[(dpidstr,srcipstr,dstipstr,dstport)] = True
        log.debug("agregando firewall regla de %s -> %s,%s en %s", srcipstr, dstipstr, dstport, dpidstr)

  # Función que permite eliminar reglas de firewall de la tabla de firewall
  def DeleteRule (self, dpidstr, macstr, srcipstr, dstipstr, dstport):
     try:
       if srcipstr == 0 and dstipstr == 0:
         del self.firewall[(dpidstr,macstr)]
         log.debug("Borrando L2-firewall regla de Src(%s) en %s", macstr, dpidstr)
       elif dstport == 0:
         del self.firewall[(dpidstr,srcipstr,dstipstr)]
         log.debug("Borrando L3-firewall regla de %s -> %s en %s", srcipstr, dstipstr, dpidstr)
       elif srcipstr == 0:
         del self.firewall[(dpidstr,dstipstr,dstport)]
         log.debug("Borrando L4-firewall regla de Dst(%s,%s) en %s", dstipstr, dstport, dpidstr)
       else:
         del self.firewall[(dpidstr,srcipstr,dstipstr,dstport)]
         log.debug("Borrando firewall regla de %s -> %s,%s en %s", srcipstr, dstipstr, dstport, dpidstr)
     except KeyError:
       log.error("No puede encontrar la Regla %s(%s) -> %s,%s en %s", srcipstr, macstr, dstipstr, dstport, dpidstr)

  # Comprueba si el paquete cumple con las reglas antes de continuar
  def CheckRule (self, dpidstr, macstr, srcipstr, dstipstr, dstport):
    # Enlace de origen bloqueado
    try:
      entry = self.firewall[(dpidstr, macstr)]
      log.info("L2-Rule Src(%s) bloqueo encontrado en %s: DROP", macstr, dpidstr)
      return entry
    except KeyError:
      pass
      #log.debug("Rule Src(%s) NO encontrada en %s: L2-Rule NO encontrada", macstr, dpidstr)

    # Host a Host bloqueado
    try:
      entry = self.firewall[(dpidstr, srcipstr, dstipstr)]
      log.info("L3-Rule (%s x->x %s) encontrada en %s: DROP", srcipstr, dstipstr, dpidstr)
      return entry
    except KeyError:
      pass
      #log.debug("Rule (%s -> %s) NO encontrada en %s: L3-Rule NO encontrada", srcipstr, dstipstr, dpidstr)

    # Proceso de destino bloqueado
    try:
      entry = self.firewall[(dpidstr, dstipstr, dstport)]
      log.info("L4-Rule Dst(%s,%s)) encontrada en %s: DROP", dstipstr, dstport, dpidstr)
      return entry
    except KeyError:
      pass
      #log.debug("Rule Dst(%s,%s) NO encontrada en %s: L4-Rule NO encontrada", dstipstr, dstport, dpidstr)
    return False

  def _handle_PacketIn (self, event):
    """
    Maneja paquetes en mensajes desde el switch para implementar el algoritmo anterior.
    """

    packet = event.parsed
    inport = event.port
    # FLood se produce cuando un enrutador utiliza un algoritmo de enrutamiento no adaptativo para enviar un paquete entrante a todos los enlaces salientes, excepto al nodo en el que llegó el paquete
    def flood (message = None):
      """ Floods el packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # solo hacer flood si hemos estado conectados un tiempo

        if self.hold_down_expired is False:
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expiro -- flooding", dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Manteniendo pulsado flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
     Descarta este paquete y, opcionalmente, instala un flow para continuar
     dejando otros similares durante un tiempo.
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_flow_mod() #crea un mensaje de moficicacion de flow
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.match.dl_dst = None
        msg.idle_timeout = 120
        msg.hard_timeout = 120
        msg.priority = 65535 #Prioridad que una regla igualará, más alto es mejor.
        msg.command = of.OFPFC_MODIFY
        msg.flags = of.OFPFF_CHECK_OVERLAP
        msg.data = event.ofp
        self.connection.send(msg)# Envia el mensaje a el switch OpenFlow 
    self.macToPort[packet.src] = event.port # 1


    dpidstr = dpid_to_str(event.connection.dpid)
    #log.debug("Conexion ID: %s" % dpidstr)

    if isinstance(packet.next, ipv4):
      log.debug("%i IP %s => %s , in switch %s", inport, packet.next.srcip,packet.next.dstip,dpidstr)
      segmant = packet.find('tcp')
      if segmant is None:
        segmant = packet.find('udp')
      if segmant is not None:
        # Cheque reglas Firewall en MAC, IPv4 and TCP Layer
        if self.CheckRule(dpidstr, packet.src, packet.next.srcip, packet.next.dstip, segmant.dstport) == True:
          drop()
          return
      else:
        # Check the Firewall Rules in MAC and IPv4 Layer
        if self.CheckRule(dpidstr, packet.src, packet.next.srcip, packet.next.dstip, 0) == True:
          drop()
          return
    elif isinstance(packet.next, arp):
      # Chequea las reglas Firewall en MAC Layer
      if self.CheckRule(dpidstr, packet.src, 0, 0, 0) == True:
        drop()
        return
      a = packet.next
      log.debug("%i ARP %s %s => %s", inport, {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
    elif isinstance(packet.next, ipv6):
      # no maneja paquetes ipv6 ipv6 
      return

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Puerto para %s desconocido -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Puerto igual para paquetes de %s -> %s en %s.%s.  Drop." % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("instalando flow para %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)

class firewall (object):
  """
  Espera a que los switches OpenFlow se conecten y los convierte en switches de aprendizaje
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Conexion %s" % (event.connection,))
    Firewall(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Inicia firewall
  """
  print("Iniciando firewall....")
  print("Importando Reglas de firewall-policies.csv......")

  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Se experaba que hold-down ser un numero")

  core.registerNew(firewall, str_to_bool(transparent))
