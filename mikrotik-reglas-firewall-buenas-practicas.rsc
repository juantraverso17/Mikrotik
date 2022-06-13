# PROTECCIÓN DEL ROUTER
# - Trabaje con  nuevas conexiones para disminuir la carga en un enrutador;
# - Crear una lista de direcciones para las IP que pueden acceder a su enrutador;
# - Habilitar el acceso ICMP (opcionalmente);
# - Elimine todo lo demás, log=yes podría agregarse a los paquetes de registro que cumplen con la regla específica;
/ip firewall filter
add action=accept chain=input comment="conexiones establecidas y relacionadas" connection-state=established,related
add action=accept chain=input src-address-list=conexiones_permitidas
add action=accept chain=input protocol=icmp
add action=drop chain=input
/ip firewall address-list
add address=10.10.10.2-10.10.10.254 list=conexiones_permitidas

# PROTECCIÓN LAN
# - lista de direcciones "ip_reservada" que usaremos para las reglas de filtrado del cortafuegos:
/ip firewall address-list
add address=0.0.0.0/8 comment="ip_reservada" list=ip_reservada
add address=172.16.0.0/12 comment="ip_reservada" list=ip_reservada
add address=192.168.0.0/16 comment="ip_reservada" list=ip_reservada
add address=10.0.0.0/8 comment="ip_reservada" list=ip_reservada
add address=169.254.0.0/16 comment="ip_reservada" list=ip_reservada
add address=127.0.0.0/8 comment="ip_reservada" list=ip_reservada
add address=224.0.0.0/4 comment="ip_reservada" list=ip_reservada
add address=198.18.0.0/15 comment="ip_reservada" list=ip_reservada
add address=192.0.0.0/24 comment="ip_reservada" list=ip_reservada
add address=192.0.2.0/24 comment="ip_reservada" list=ip_reservada
add address=198.51.100.0/24 comment="ip_reservada" list=ip_reservada
add address=203.0.113.0/24 comment="ip_reservada" list=ip_reservada
add address=100.64.0.0/10 comment="ip_reservada" list=ip_reservada
add address=240.0.0.0/4 comment="ip_reservada" list=ip_reservada
add address=192.88.99.0/24 comment="ip_reservada" list=ip_reservada
# - Paquetes con estado de conexión = establecido, relacionados agregados a FastTrack para un rendimiento de datos más rápido, el firewall funcionará solo con conexiones nuevas;
# - Elimine la conexión no válida y regístrela con el prefijo "no válido";
# - Elimine los intentos de llegar a direcciones no públicas desde su red local, aplique address-list=ip_reservada antes, "bridge" es la interfaz de red local, log=sí intenta con el prefijo "!public_from_LAN";
# - Descarte los paquetes entrantes que no son NAT`ed, ether1 es una interfaz pública, registre los intentos con el prefijo "!NAT";
# - Saltar a la cadena ICMP para eliminar mensajes ICMP no deseados
# - Eliminar los paquetes entrantes de Internet, que no son direcciones IP públicas, ether1 es una interfaz pública, registrar los intentos con el prefijo "!public";
# - Descartar paquetes de LAN que no tiene IP de LAN, 10.10.10.0/24 es una subred utilizada en la red local;
/ip firewall filter
add action=fasttrack-connection chain=forward comment="FastTrack" connection-state=established,related
add action=accept chain=forward comment="Establecido, Relacionado" connection-state=established,related
add action=drop chain=forward comment="Descartar inválidos" connection-state=invalid log=yes log-prefix=invalid
add action=drop chain=forward comment="Descartar intentos de llegar a ip no pública desde LAN" dst-address-list=ip_reservada in-interface=bridge log=yes log-prefix=!public_from_LAN out-interface=!bridge
add action=drop chain=forward comment="Descartar los paquetes entrantes que no están NATeados" connection-nat-state=!dstnat connection-state=new in-interface=ether1 log=yes log-prefix=!NAT
add action=jump chain=forward protocol=icmp jump-target=icmp comment="Saltar a reglas de ICMP"
add action=drop chain=forward comment="Descartar paquetes entrantes de Internet que no son de una IP pública" in-interface=ether1 log=yes log-prefix=!public src-address-list=ip_reservada
add action=drop chain=forward comment="Descartar paquetes de LAN que no tienen IP de LAN" in-interface=bridge log=yes log-prefix=LAN_!LAN src-address=!10.10.10.0/24
# - Reglas ICMP
/ip firewall filter
add chain=icmp protocol=icmp icmp-options=0:0 action=accept comment="echo reply"
add chain=icmp protocol=icmp icmp-options=3:0 action=accept comment="net unreachable"
add chain=icmp protocol=icmp icmp-options=3:1 action=accept comment="host unreachable"
add chain=icmp protocol=icmp icmp-options=3:4 action=accept comment="host unreachable fragmentation required"
add chain=icmp protocol=icmp icmp-options=8:0 action=accept comment="allow echo request"
add chain=icmp protocol=icmp icmp-options=11:0 action=accept comment="allow time exceed"
add chain=icmp protocol=icmp icmp-options=12:0 action=accept comment="allow parameter bad"
add chain=icmp action=drop comment="deny all other types"