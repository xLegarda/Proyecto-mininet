from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import threading
import datetime
import matplotlib.pyplot as plt
import numpy as np

#Este es nuestro diccionario para el contador de nuestros servidores. 
dictReq ={}
# Esta es nuestra clase principal para el balanceador de carga
class LoadBalancer(object):
	global dictReq
	def __init__(self, service_ip, server_ips = [],weights=[],flag=0): #inicializa 10.1.2.3 y los servidores
		core.openflow.addListeners(self)# Escuchamos el Paquete, y por ende la conexion
		#Inicialización de diferentes diccionarios y otras cosas
		self.macToPort = {} 		#Tabla para almacenar IP Mac y ouport después de la solicitud
		self.client_table={} 		#diccionario para manejar clientes en Balanceador de carga
		self.lb_map={}
		self.lb_real_ip=service_ip 					# la real ip del Balanceador de carga
		self.server_ips=server_ips 					# Una lista contiene los servidores de entrada 
		self.total_servers=len(server_ips) 			        # la longitud de los servidores
		self.flag=flag
		self.total_weight = sum(weights) # Cambiar para establecer igual a la suma de la carga
		self.current_weight = 0
		self.weights = weights # Almacena las cargas aquí según el orden ascendente de la ip para todas las ips del servidor
		self.current_sends = [0 for i in range(self.total_servers)]
		self.current_server_index = 0

	# Conecta el controlador con el conmutador y los servidores flood con solicitudes arp
	def _handle_ConnectionUp(self, event): 					#nueva conexion de switch
		self.lb_mac = EthAddr("0A:00:00:00:00:01") 			#Mac falso del balanceador de cargo
		self.connection = event.connection
		self.ethernet_broad=EthAddr("ff:ff:ff:ff:ff:ff") 	#MAC de difusión para transmitir a todas las interfaces posibles
		for ip in self.server_ips:
			selected_server_ip= ip
			self.send_proxied_arp_request(self.connection,selected_server_ip) #las solicitudes flood ARP a todos los servidores para que coincidan con Ips con mac y puertos
	

	# El trabajo de aqui empieza cuando se salga de mininet
	def _handle_ConnectionDown (self, event): 
		N = self.total_servers
		
		std = (0, 0, 0, 0)

		ind = np.arange(N)  # Las ubicaciones X para los grupos
		width = 0.5       # el ancho de las barras

		fig, ax = plt.subplots()
		rects1 = ax.bar(ind, dictReq.values(), width, color='r', yerr=std)

		# Agregue texto para titulo del grafico, etiquetas del eje y títulos de eje
		ax.set_ylabel('Solicitudes')
		ax.set_xlabel('IPs')
		ax.set_title('Solicitudes por servidor IP')
		ax.set_xticks(ind + width / 2)
		ax.set_xticklabels(dictReq.keys())

		# Sube el archivo al directorio en el que estamos.
		fig.savefig("grafico.png")
		plt.show()





	def update_lb_mapping(self, client_ip): 					#actualiza el mapa de balanceo de carga
	
	# To change here
		if client_ip in self.client_table.keys():
			if self.current_weight == self.total_weight:
				self.current_sends = [0 for i in range(self.total_servers)]
				self.current_weight = 0
			while (self.current_sends[self.current_server_index] >= self.weights[self.current_server_index]):
				self.current_server_index = (self.current_server_index + 1) % self.total_servers
			
			self.current_weight += 1
			self.current_sends[self.current_server_index] += 1
			server = self.server_ips[self.current_server_index]
			self.current_server_index = (self.current_server_index + 1) % self.total_servers
			log.info(" Redirigido a  %s "% server)
			dictReq.update({str(server):(dictReq[str(server)] + 1)})
			self.lb_map[client_ip]=server		#Pasar a un diccionario el servidor aleatorio y la IP del cliente


	#Se crea un paquete de respuesta ARP y se envía mediante proxy con el paquete de salida del controlador	
	def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
		# respuesta a la solicitud de ARP 
		r=arp();
		r.hwtype = r.HW_TYPE_ETHERNET 	# Tipo de hardware
		r.prototype = r.PROTO_TYPE_IP 	# tipo de protocolo
		r.hwlen = 6  					# La longitud de la dirección de hardware es 6 bytes y MAC=IPv6
		r.protolen = r.protolen 		# La longitud del ipv4
		r.opcode = r.REPLY				# El paquete tiene el tipo de respuesta 

		r.hwdst = packet.src  
		r.hwsrc =requested_mac				# Falsa mac
		
		r.protosrc = packet.payload.protodst 
		r.protodst = packet.payload.protosrc

		e = ethernet(type=packet.ARP_TYPE, src=requested_mac, dst=packet.src)
		e.set_payload(r)
		
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		# envia el mensaje a través del puerto de salida del cliente
		msg.actions.append(of.ofp_action_output(port =of.OFPP_IN_PORT)) # En el que los clientes del puerto pueden oír
		msg.in_port = outport
		connection.send(msg)
		  	
	#Enviar flood de solicitudes ARP para conocer macth ip mac puerto de servidores
	def send_proxied_arp_request(self, connection, ip):
											#construir el paquete arp 
		ar=arp() 							# tipo de paquete
		ar.hwtype = ar.HW_TYPE_ETHERNET 	# tipo de hardware
		ar.prototype = ar.PROTO_TYPE_IP 	# tipo de protocolo
		ar.hwlen = 6  						# La longitud de la dirección de hardware es 6 bytes y MAC=IPv6
		ar.protolen = ar.protolen 			# La longitud del ipv4
		ar.opcode = ar.REQUEST
		ar.hwdst = self.ethernet_broad 		# broadcast de todas las posibles interfaces
		ar.protodst = ip 					# ip de destino a enviar 
		ar.hwsrc = self.lb_mac 				# falsa direccion mac
		ar.protosrc = self.lb_real_ip 		# La ip real de la direccion

											# contenido del paquete
		e = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac, dst=self.ethernet_broad)
		e.set_payload(ar) 					# Toma el paquete anterior y lo pone en los datos del mensaje
		
		msg = of.ofp_packet_out() 			# Envia los paquetes salientes porque no necesitan una entrada en la tabla de flow
		msg.data = e.pack()			
		msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST,ip)) 	# lo envia a esta ip
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 		# flood a todos los puertos
		
		connection.send(msg)
		

	# Instala la regla de flow del cliente al servidor.
	def install_flow_rule_client_to_server(self,event, connection, outport, client_ip, 
						server_ip, buffer_id=of.NO_BUFFER):				
		self.install_flow_rule_server_to_client(connection, event.port, server_ip,client_ip)
		
		msg=of.ofp_flow_mod() 				# La forma en la que el mensaje sera enviado
		msg.idle_timeout=3
		msg.hard_timeout=1				# Si no, este vínculo no se utiliza despues de 1 segundo Elimina regla del flow
		msg.command=of.OFPFC_ADD			# Dice al conmutador a agregar la regla
		msg.buffer_id=buffer_id				# Define el bufer
		
											# Que data va a tener el paquete 
		msg.match.dl_type=ethernet.IP_TYPE	# Hace coincidir el tipo de IP		
		msg.match.nw_src=client_ip 			# Hace coincidir el origen de la direccion de red del mensaje para la regla
		msg.match.nw_dst=self.lb_real_ip	# Hace coincidir la ip de networkdst para la regla

		msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 		# Desde que mac el mensaje sera enviado (falsa mac)
		msg.actions.append(of.ofp_action_dl_addr.set_dst(self.macToPort[server_ip].get('server_mac'))) # Respuesta a la direccion de los servidores
		
		msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) 		# Enviara el paquete a este servidor con ip 		
		
		msg.actions.append(of.ofp_action_output(port=outport)) 				# El puerto que el paquete pasara 
		
		self.connection.send(msg)

		#log.info("Instalar regla flow del Cliente: %s -------> Servidor: %s"%(client_ip,server_ip))


	# Instala la regla de flow del servidor al cliente.
	def install_flow_rule_server_to_client(self, connection, outport, server_ip, 
						client_ip, buffer_id=of.NO_BUFFER):
		msg=of.ofp_flow_mod()
		msg.command=of.OFPFC_ADD
		
		msg.match.dl_type=ethernet.IP_TYPE 	# Hace coincidir el tipo de IP		
		msg.match.nw_src=server_ip			# Hace coincidir el origen de la direccion de red del mensaje 
		msg.match.nw_dst=client_ip			# Hace coincidir la ip de networkdst
		msg.idle_timeout=10 				# if not this link not used afte 10sec delete rule from flow
		msg.buffer_id= buffer_id			# Define el bufer
		
		msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 					# Desde que mac el mensaje sera enviado (falsa mac)
		msg.actions.append(of.ofp_action_dl_addr.set_dst(self.client_table[client_ip].get('client_mac'))) 		# Respuesta a la direccion MAC de los clientes s
		
		msg.actions.append(of.ofp_action_nw_addr.set_src(self.lb_real_ip)) 				# Responde con la ip del balanceador de carga
		msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip)) 					# Enviara el paquete a este cliente con ip 		
		
		msg.actions.append(of.ofp_action_output(port=outport))							# El puerto que el paquete pasara 
		
		self.connection.send(msg)
		#log.info("Regla de Flow del Servidor: %s -------> Cliente: %s"%(server_ip,client_ip))


	# Maneja los paquetes que vienen
	def _handle_PacketIn(self, event):
			packet = event.parsed
			connection = event.connection
			inport = event.port					# El puerto que viene del paquete
			if packet.type == packet.ARP_TYPE:
				response=packet.payload			# Desencapsula el paquete entrante
				if response.opcode==response.REPLY:											# Toma la respuesta y la pasa al diccionario
					if response.protosrc not in self.macToPort.keys(): 				# Comprueba si la respuesta arp arps está en el diccionario y, si no, la inserta
						self.macToPort[IPAddr(response.protosrc)]={'server_mac':EthAddr(response.hwsrc),'port':inport}					
			
				elif response.opcode==response.REQUEST: 			# Si hay una solicitud arp el balanceador de carga deberia saber que hacer				
					
					if response.protosrc not in self.macToPort.keys()and response.protosrc not in self.client_table.keys():
						self.client_table[response.protosrc]={'client_mac':EthAddr(packet.payload.hwsrc),'port':inport}		#Inserta el MAC IP del cliente y el puerto en una tabla de reenvío
										
					if (response.protosrc in self.client_table.keys()and response.protodst == self.lb_real_ip): 			#Si el origen de la solicitud es cliente y no servidor y el destinario es el balanceador de carga 
						#log.info("Cliente %s envia solicitud ARP al switch %s"%(response.protosrc,response.protodst))
						self.send_proxied_arp_reply(packet,connection,inport,self.lb_mac)					# Envia la respuesta arp rely al ip que queremos
					
					elif response.protosrc in self.macToPort.keys() and response.protodst in self.client_table.keys(): # El servidor envía solicitudes ARP a los clientes para aprender su MAC
						#log.info("Servidor %s envia solicitud ARP al cliente"%response.protosrc)
						self.send_proxied_arp_reply(packet,connection,inport,self.lb_mac)
					else:
						log.info("Invalida solicitud ARP ")
			elif packet.type == packet.IP_TYPE:
				# Configura ruta del cliente al servidor
				if (packet.next.dstip== self.lb_real_ip) and (packet.next.srcip not in self.macToPort.keys()) :	
				#Compruebe si el destinatario es la IP del conmutador y el origen, no un servidor
					msg=of.ofp_packet_out()
					msg.buffer_id = event.ofp.buffer_id
					if self.flag!=0:
						self.update_lb_mapping(packet.next.srcip)					# Tome la IP de origen del paquete (el host) y actualiza la asignación
					else:
						self.update_lb_mapping_random(packet.next.srcip)
					client_ip=packet.payload.srcip
					server_ip=self.lb_map.get(packet.next.srcip)
					outport=int(self.macToPort[server_ip].get('port'))
					self.install_flow_rule_client_to_server(event,connection, outport, client_ip,server_ip)
					e = ethernet(type=ethernet.IP_TYPE, src=self.lb_mac, dst=self.macToPort[server_ip].get('server_mac'))
					e.set_payload(packet.next)
					msg.data=e.pack()
					msg.in_port=inport
					msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 		#Desde qué Mac se enviará el mensaje (Mac falso)
					msg.actions.append(of.ofp_action_dl_addr.set_dst(self.macToPort[server_ip].get('server_mac'))) # La direccion de los servidores
			
					msg.actions.append(of.ofp_action_nw_addr.set_src(client_ip))		# Qué cliente enviará el paquete
					msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) 		# Enviará el paquete a esta IP del servidor		
					msg.actions.append(of.ofp_action_output(port=outport))	
					connection.send(msg)
					
				# Configurar reversa
				elif packet.next.dstip in self.client_table.keys() : #servidor al cliente
					if packet.next.srcip in self.macToPort.keys(): 
						server_ip=packet.next.srcip #Tomar el paquete de origen del mensaje
						client_ip=self.lb_map.keys()[list(self.lb_map.values()).index(packet.next.srcip)]
						outport=int(self.client_table[client_ip].get('port'))
						self.install_flow_rule_server_to_client(connection, outport, server_ip,client_ip)							
						
						# Paquete de salida porque de lo contrario se perdera un paquete de la otra manera es usar el identificador de búfer
						e = ethernet(type=ethernet.IP_TYPE, src=self.lb_mac, dst=self.macToPort[server_ip].get('server_mac'))
						e.set_payload(packet.next)
						
						msg=of.ofp_packet_out()
						msg.buffer_id = event.ofp.buffer_id
						msg.data=e.pack()
						msg.in_port=inport
						
						msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 					# Desde qué Mac se enviará el mensaje (Mac falso)
						msg.actions.append(of.ofp_action_dl_addr.set_dst(self.client_table[client_ip].get('client_mac'))) 	# Respuesta a la Dirección MAC de los clientes
			
						msg.actions.append(of.ofp_action_nw_addr.set_src(self.lb_real_ip)) 				# Respuesta con la ip del balanceador de carga  
						msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip)) 				# Va a enviar el paquete a esta direccion de cliente
						msg.actions.append(of.ofp_action_output(port=outport))                                  
				   	     	#el puerto por el que pasará el paquete 
			
						self.connection.send(msg)
			else:
				#log.info("Paquete de tipo desconocido: %s" % packet.type)
				return
			return


#lanza la aplicacion con los siguientes argumentos:	
#ip: ip publica, servers: direcciones ip de servidores (en formato String)
def launch(ip, servers,weights="",mode=""): 
	log.info("Cargando Modulo Simple Balanceador de Carga")
	server_ips = servers.replace(","," ").split()
	flag=0
	weights = weights.replace(","," ").split()
	weights = [int(x) for x in weights]
	if(mode!="random"):
		flag=1
		
		if(len(server_ips)!=len(weights)):
			print("Por favor suministre la carga correspondiente tambien")
			return
		#print(weights)
		wt = [(server_ips[i],weights[i]) for i in range(len(server_ips))]
		wt.sort()
		for i in range(len(wt)):
			server_ips[i],weights[i]=wt[i]
	
	for i in server_ips:
		dictReq[i]=0
	
	server_ips = [IPAddr(x) for x in server_ips]
	service_ip = IPAddr(ip)
	core.registerNew(LoadBalancer, service_ip, server_ips,weights,flag)
