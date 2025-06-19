# main.py

import yaml
import requests
import json
import uuid
import sys

# --- Configuración Global ---
# IP del controlador Floodlight. Reemplazar con la IP real.
FLOODLIGHT_IP = "10.20.12.62"
FLOODLIGHT_PORT = 8080
BASE_URL = f"http://{FLOODLIGHT_IP}:{FLOODLIGHT_PORT}"
STATIC_FLOW_URL = f"{BASE_URL}/wm/staticflowpusher/json"
DEVICE_API_URL = f"{BASE_URL}/wm/device/"
ROUTE_API_URL = f"{BASE_URL}/wm/topology/route"

# Timeout para las peticiones al controlador
REQUEST_TIMEOUT = 5
# Flag para activar/desactivar la comunicación real con Floodlight
FLOODLIGHT_ENABLED = True 

# --- Modelos de Datos (Clases) ---

class Alumno:
    """Modela a un alumno con su información básica."""
    def __init__(self, codigo, nombre, mac):
        self.codigo = str(codigo)
        self.nombre = nombre
        self.mac = mac.upper() # Estandarizar MAC a mayúsculas

    def __str__(self):
        return f"  - Código: {self.codigo}, Nombre: {self.nombre}, MAC: {self.mac}"

class Servicio:
    """Modela un servicio ofrecido por un servidor."""
    def __init__(self, nombre, protocolo, puerto):
        self.nombre = nombre
        self.protocolo = protocolo
        self.puerto = puerto

    def __str__(self):
        return f"    - Servicio: {self.nombre} (Protocolo: {self.protocolo}, Puerto: {self.puerto})"

class Servidor:
    """Modela un servidor de la red."""
    def __init__(self, nombre, ip, mac):
        self.nombre = nombre
        self.ip = ip
        self.mac = mac.upper()
        self.servicios = {} # {nombre_servicio: Objeto Servicio}

    def agregar_servicio(self, servicio):
        self.servicios[servicio.nombre] = servicio

    def __str__(self):
        return f"  - Servidor: {self.nombre}, IP: {self.ip}, MAC: {self.mac}"

class Curso:
    """Modela un curso, incluyendo alumnos y políticas de servidor."""
    def __init__(self, codigo, nombre, estado):
        self.codigo = str(codigo)
        self.nombre = nombre
        self.estado = estado
        self.alumnos = []  # Lista de códigos de alumnos
        self.servidores_politicas = {} # {nombre_servidor: [servicios_permitidos]}

    def __str__(self):
        return f"  - Código: {self.codigo}, Nombre: {self.nombre}, Estado: {self.estado}"

# --- Clase Principal de Gestión ---

class NetworkPolicyManager:
    """
    Clase central que gestiona los datos de la red (alumnos, cursos, servidores)
    y las conexiones activas.
    """
    def __init__(self):
        self.alumnos = {}
        self.cursos = {}
        self.servidores = {}
        self.conexiones = {}

    def importar_datos(self, filename):
        """(*) Carga y parsea los datos desde un archivo YAML."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data is None: return False
        except (FileNotFoundError, yaml.YAMLError) as e:
            print(f"Error al procesar el archivo '{filename}': {e}")
            return False

        self.alumnos = { str(a['codigo']): Alumno(a['codigo'], a['nombre'], a['mac']) for a in data.get('alumnos', []) }
        self.servidores = { s['nombre']: Servidor(s['nombre'], s['ip'], s.get('mac', '00:00:00:00:00:00')) for s in data.get('servidores', []) }
        for s_data in data.get('servidores', []):
            servidor = self.servidores.get(s_data['nombre'])
            if servidor:
                for svc_data in s_data.get('servicios', []):
                    servidor.agregar_servicio(Servicio(svc_data['nombre'], svc_data['protocolo'], svc_data['puerto']))

        for c_data in data.get('cursos', []):
            curso = Curso(c_data['codigo'], c_data['nombre'], c_data['estado'])
            curso.alumnos = [str(a) for a in c_data.get('alumnos', [])]
            curso.servidores_politicas = {sp['nombre']: sp.get('servicios_permitidos', []) for sp in c_data.get('servidores', [])}
            self.cursos[str(curso.codigo)] = curso
            
        print(f"Datos importados correctamente desde '{filename}'.")
        return True

    def _get_attachment_point(self, host_mac):
        """Obtiene el punto de conexión (DPID, puerto) de un host a través de su MAC."""
        print(f"Buscando punto de conexión para {host_mac}...")
        try:
            response = requests.get(DEVICE_API_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            devices = response.json()
            for device in devices:
                if host_mac.upper() in [mac.upper() for mac in device.get('mac', [])]:
                    ap_list = device.get('attachmentPoint', [])
                    if ap_list:
                        ap = ap_list[0]
                        dpid = ap.get('switchDPID')
                        port = ap.get('port')
                        print(f"  > Encontrado: DPID={dpid}, Puerto={port}")
                        return dpid, str(port)
            print(f"  > Punto de conexión para {host_mac} no encontrado.")
            return None, None
        except requests.RequestException as e:
            print(f"Error al obtener dispositivos de Floodlight: {e}")
            return None, None

    def _get_route(self, src_dpid, src_port, dst_dpid, dst_port):
        """Obtiene la ruta entre dos puntos de la topología."""
        url = f"{ROUTE_API_URL}/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
        print(f"Solicitando ruta: {src_dpid}/{src_port} -> {dst_dpid}/{dst_port}")
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            route = response.json()
            if route:
                print(f"  > Ruta encontrada con {len(route) // 2} saltos.")
                return route
            else:
                print("  > No se encontró una ruta.")
                return None
        except requests.RequestException as e:
            print(f"Error al obtener la ruta de Floodlight: {e}")
            return None

    def _enviar_peticion_floodlight(self, metodo, payload):
        """Función helper para enviar peticiones a Floodlight."""
        if not FLOODLIGHT_ENABLED:
            print(f"\n[SIMULACIÓN] Método: {metodo.upper()}, Payload: {json.dumps(payload)}")
            return True
        try:
            if metodo == 'post':
                response = requests.post(STATIC_FLOW_URL, json=payload, timeout=REQUEST_TIMEOUT)
            elif metodo == 'delete':
                headers = {'Content-Type': 'application/json'}
                response = requests.delete(STATIC_FLOW_URL, data=json.dumps(payload), headers=headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            print(f"  > Floodlight respondió: {response.json().get('status', 'OK')}")
            return True
        except requests.RequestException as e:
            print(f"  > Error en petición a Floodlight: {e}")
            return False

    def crear_conexion(self, codigo_alumno, nombre_servidor, nombre_servicio):
        """(*) Valida y crea una conexión instalando flujos en Floodlight."""
        print("\n--- Creando Conexión ---")
        alumno = self.alumnos.get(str(codigo_alumno))
        servidor = self.servidores.get(nombre_servidor)
        if not all([alumno, servidor, nombre_servicio in servidor.servicios]):
            print("Error: Alumno, servidor o servicio no encontrado.")
            return
        if not self.verificar_autorizacion(codigo_alumno, nombre_servidor, nombre_servicio):
            print(f"Error: Alumno '{codigo_alumno}' NO AUTORIZADO para acceder a '{nombre_servicio}' en '{nombre_servidor}'.")
            return
        print(f"Éxito: Alumno '{alumno.nombre}' ({codigo_alumno}) está autorizado.")
        
        handler = f"{nombre_servicio}-{alumno.codigo}-{uuid.uuid4().hex[:6]}"
        servicio = servidor.servicios.get(nombre_servicio)
        
        flujos_a_instalar = []

        # --- LÓGICA DINÁMICA CON FLOODLIGHT ---
        if FLOODLIGHT_ENABLED:
            punto_alumno = self._get_attachment_point(alumno.mac)
            punto_servidor = self._get_attachment_point(servidor.mac)
            if not all([punto_alumno, punto_servidor, punto_alumno[0], punto_servidor[0]]):
                print("Error: No se pudo localizar a ambos hosts en la red. No se puede crear la ruta.")
                return
            
            # Obtener attachment points del alumno y servidor
            (dpid_alumno, puerto_ap_alumno) = punto_alumno
            (dpid_servidor, puerto_ap_servidor) = punto_servidor

            # Obtener la ruta en ambas direcciones
            # La ruta de Floodlight incluye el AP de origen como primer salto y el AP de destino como último.
            ruta_directa = self._get_route(dpid_alumno, puerto_ap_alumno, dpid_servidor, puerto_ap_servidor)
            ruta_inversa = self._get_route(dpid_servidor, puerto_ap_servidor, dpid_alumno, puerto_ap_alumno)

            if not ruta_directa or not ruta_inversa:
                print("Error: No se pudo calcular la ruta completa (directa e inversa).")
                return

            proto_map = {"TCP": "6", "UDP": "17"}
            ip_proto = proto_map.get(servicio.protocolo.upper(), "6")

            # CORRECTED LOGIC: Construir flujos para la ruta directa (alumno -> servidor)
            for i in range(0, len(ruta_directa), 2):
                dpid = ruta_directa[i]['switch']
                # El puerto de SALIDA es el del siguiente punto en la ruta (el puerto egress del enlace)
                out_port = str(ruta_directa[i+1]['port']['portNumber'])
                
                # Flujo de servicio
                flow_svc = {"switch": dpid, "name": f"{handler}-fwd-svc-{i//2}", "priority": "32768", "active": "true",
                            "eth_type": "0x0800", "eth_src": alumno.mac, "eth_dst": servidor.mac,
                            "ipv4_dst": servidor.ip,
                            "ip_proto": f"0x{ip_proto}", f"{servicio.protocolo.lower()}_dst": str(servicio.puerto),
                            "actions": f"output={out_port}"}
                flujos_a_instalar.append(flow_svc)
                # Flujo ARP
                flow_arp = {"switch": dpid, "name": f"{handler}-fwd-arp-{i//2}", "priority": "32767", "active": "true",
                            "eth_type": "0x0806", "eth_src": alumno.mac, "eth_dst": servidor.mac,
                            "actions": f"output={out_port}"}
                flujos_a_instalar.append(flow_arp)

            # CORRECTED LOGIC: Construir flujos para la ruta inversa (servidor -> alumno)
            for i in range(0, len(ruta_inversa), 2):
                dpid = ruta_inversa[i]['switch']
                # El puerto de SALIDA es el del siguiente punto en la ruta
                out_port = str(ruta_inversa[i+1]['port']['portNumber'])

                flow_svc = {"switch": dpid, "name": f"{handler}-rev-svc-{i//2}", "priority": "32768", "active": "true",
                            "eth_type": "0x0800", "eth_src": servidor.mac, "eth_dst": alumno.mac,
                            "ipv4_src": servidor.ip,
                            "ip_proto": f"0x{ip_proto}", f"{servicio.protocolo.lower()}_src": str(servicio.puerto),
                            "actions": f"output={out_port}"}
                flujos_a_instalar.append(flow_svc)
                flow_arp = {"switch": dpid, "name": f"{handler}-rev-arp-{i//2}", "priority": "32767", "active": "true",
                            "eth_type": "0x0806", "eth_src": servidor.mac, "eth_dst": alumno.mac,
                            "actions": f"output={out_port}"}
                flujos_a_instalar.append(flow_arp)
        
        # --- LÓGICA ESTÁTICA SIMULADA (No cambia) ---
        else:
            dpid, out_port_fwd, out_port_rev = "00:00:00:00:00:00:00:01", "3", "1"
            proto_map = {"TCP": "6", "UDP": "17"}
            ip_proto = proto_map.get(servicio.protocolo.upper(), "6")

            flujos_a_instalar = [
                {"switch": dpid, "name": handler, "priority": "32768", "active": "true", "eth_type": "0x0800", "ipv4_dst": servidor.ip, "eth_src": alumno.mac, "ip_proto": f"0x{ip_proto}", f"{servicio.protocolo.lower()}_dst": str(servicio.puerto), "actions": f"output={out_port_fwd}"},
                {"switch": dpid, "name": f"{handler}-ret", "priority": "32768", "active": "true", "eth_type": "0x0800", "ipv4_src": servidor.ip, "eth_dst": alumno.mac, "ip_proto": f"0x{ip_proto}", f"{servicio.protocolo.lower()}_src": str(servicio.puerto), "actions": f"output={out_port_rev}"},
                {"switch": dpid, "name": f"arp-{handler}", "priority": "32767", "active": "true", "eth_type": "0x0806", "eth_src": alumno.mac, "eth_dst": servidor.mac, "actions": f"output={out_port_fwd}"},
                {"switch": dpid, "name": f"arp-{handler}-ret", "priority": "32767", "active": "true", "eth_type": "0x0806", "eth_src": servidor.mac, "eth_dst": alumno.mac, "actions": f"output={out_port_rev}"}
            ]

        # --- INSTALACIÓN DE FLUJOS ---
        print(f"Generando {len(flujos_a_instalar)} flujos para la conexión '{handler}'...")
        exito_total = True
        for flow in flujos_a_instalar:
            print(f"Instalando flujo: {flow['name']} en switch {flow['switch']}")
            if not self._enviar_peticion_floodlight('post', flow):
                exito_total = False
                print(f"Error al instalar el flujo {flow['name']}. Abortando y limpiando.")
                self.borrar_conexion(handler, cleanup_on_fail=True)
                break
        
        if exito_total:
            self.conexiones[handler] = { "alumno": codigo_alumno, "servidor": nombre_servidor, "servicio": nombre_servicio, "flujos": [f['name'] for f in flujos_a_instalar] }
            print(f"\nConexión '{handler}' creada y registrada exitosamente.")
    
    # El resto de las funciones de la clase (listar_alumnos, listar_cursos, etc.) permanecen igual...

    def listar_conexiones(self):
        """(*) Muestra las conexiones manuales activas."""
        print("\n--- Conexiones Activas Creadas Manualmente ---")
        if not self.conexiones:
            print("No hay conexiones activas registradas en la aplicación.")
            return
        for handler, details in self.conexiones.items():
            alumno = self.alumnos.get(details['alumno'])
            nombre_alumno = f"{alumno.nombre} ({alumno.codigo})" if alumno else details['alumno']
            num_flujos = len(details.get('flujos', []))
            print(f"  - Handler: {handler} ({num_flujos} flujos instalados)")
            print(f"    De: Alumno {nombre_alumno}")
            print(f"    A : Servicio {details['servicio']} en {details['servidor']}")

    def borrar_conexion(self, handler, cleanup_on_fail=False):
        """(*) Elimina una conexión existente y sus flujos."""
        connection_details = self.conexiones.get(handler)
        if not cleanup_on_fail and not connection_details:
            print(f"Error: Conexión con handler '{handler}' no encontrada.")
            return

        print(f"\n--- Borrando Conexión '{handler}' ---")
        
        # Nombres de los flujos a eliminar
        nombres_flujos = connection_details.get('flujos', []) if connection_details else [handler, f"{handler}-ret", f"arp-{handler}", f"arp-{handler}-ret"]
        
        for name in nombres_flujos:
            payload = {'name': name}
            print(f"Eliminando flujo: {name}")
            self._enviar_peticion_floodlight('delete', payload)

        if handler in self.conexiones:
            del self.conexiones[handler]
            print(f"Conexión '{handler}' eliminada del registro de la aplicación.")
    
    # El resto del código del menú y la función main permanece sin cambios significativos...
    def listar_alumnos(self, filtro_curso=None):
        """(*) Lista todos los alumnos o filtra por curso."""
        print("\n--- Listado de Alumnos ---")
        if not self.alumnos:
            print("No hay alumnos cargados.")
            return

        alumnos_a_mostrar = []
        if filtro_curso:
            curso = self.cursos.get(str(filtro_curso))
            if not curso:
                print(f"Error: Curso '{filtro_curso}' no encontrado.")
                return
            print(f"Alumnos en el curso {filtro_curso} ({curso.nombre}):")
            for codigo_alumno in curso.alumnos:
                if codigo_alumno in self.alumnos:
                    alumnos_a_mostrar.append(self.alumnos[codigo_alumno])
        else:
            print("Todos los alumnos:")
            alumnos_a_mostrar = list(self.alumnos.values())
        
        if not alumnos_a_mostrar:
            print("No se encontraron alumnos para el filtro especificado.")
        else:
            for alumno in alumnos_a_mostrar:
                print(alumno)
    
    def agregar_alumno(self, codigo, nombre, mac):
        """(*) Agrega un nuevo alumno al sistema."""
        codigo_str = str(codigo)
        if codigo_str in self.alumnos:
            print(f"Error: El alumno con código '{codigo_str}' ya existe.")
            return
        self.alumnos[codigo_str] = Alumno(codigo_str, nombre, mac)
        print(f"Alumno '{nombre}' (código: {codigo_str}) agregado correctamente.")

    def listar_cursos(self):
        """(*) Lista todos los cursos existentes."""
        print("\n--- Listado de Cursos ---")
        if not self.cursos:
            print("No hay cursos cargados.")
            return
        for curso in self.cursos.values():
            print(curso)

    def mostrar_detalle_curso(self, codigo):
        """(*) Muestra los detalles de un curso, incluyendo sus alumnos."""
        curso = self.cursos.get(str(codigo))
        if not curso:
            print(f"Error: Curso con código '{codigo}' no encontrado.")
            return
        print(f"\n--- Detalles del Curso: {curso.nombre} ({curso.codigo}) ---")
        print(f"Estado: {curso.estado}")
        print("Alumnos Matriculados:")
        if curso.alumnos:
            for al_codigo in curso.alumnos:
                alumno = self.alumnos.get(al_codigo)
                if alumno:
                    print(f"  - {al_codigo} ({alumno.nombre})")
                else:
                    print(f"  - {al_codigo} (Alumno no encontrado en la base de datos)")
        else:
            print("  - No hay alumnos matriculados.")
        print("Políticas de Acceso:")
        if curso.servidores_politicas:
            for servidor, servicios in curso.servidores_politicas.items():
                print(f"  - Servidor: {servidor} -> Servicios permitidos: {', '.join(servicios)}")
        else:
            print("  - No hay políticas de acceso definidas.")

    def actualizar_curso(self, codigo):
        """(*) Permite agregar o eliminar un alumno de un curso."""
        curso = self.cursos.get(str(codigo))
        if not curso:
            print(f"Error: Curso con código '{codigo}' no encontrado.")
            return
        
        accion = input("¿Desea (a)gregar o (e)liminar un alumno? ").lower().strip()
        codigo_alumno = input("Ingrese el código del alumno: ").strip()

        if codigo_alumno not in self.alumnos:
            print("Error: El alumno no existe en la base de datos general.")
            return

        if accion == 'a':
            if codigo_alumno in curso.alumnos:
                print("El alumno ya está en el curso.")
            else:
                curso.alumnos.append(codigo_alumno)
                print(f"Alumno '{self.alumnos[codigo_alumno].nombre}' agregado al curso '{curso.nombre}'.")
        elif accion == 'e':
            if codigo_alumno in curso.alumnos:
                curso.alumnos.remove(codigo_alumno)
                print(f"Alumno '{self.alumnos[codigo_alumno].nombre}' eliminado del curso '{curso.nombre}'.")
            else:
                print("El alumno no se encontraba en este curso.")
        else:
            print("Opción no válida. Debe ser 'a' o 'e'.")

    def listar_servidores(self):
        """(*) Lista todos los servidores."""
        print("\n--- Listado de Servidores ---")
        if not self.servidores:
            print("No hay servidores cargados.")
            return
        for servidor in self.servidores.values():
            print(servidor)

    def mostrar_detalle_servidor(self, nombre):
        """(*) Muestra los detalles y servicios de un servidor."""
        servidor = self.servidores.get(nombre)
        if not servidor:
            print(f"Error: Servidor '{nombre}' no encontrado.")
            return
        print(f"\n--- Detalles del Servidor: {servidor.nombre} ---")
        print(f"IP: {servidor.ip}")
        print("Servicios ofrecidos:")
        if servidor.servicios:
            for servicio in servidor.servicios.values():
                print(servicio)
        else:
            print("  - No hay servicios configurados para este servidor.")
            
    def listar_cursos_por_servicio(self, nombre_servidor, nombre_servicio):
        """(*) Busca y lista los cursos que permiten un servicio específico en un servidor."""
        print(f"\n--- Cursos con acceso a '{nombre_servicio}' en '{nombre_servidor}' ---")
        encontrado = False
        for curso in self.cursos.values():
            politicas = curso.servidores_politicas.get(nombre_servidor, [])
            if nombre_servicio in politicas:
                print(f"  - {curso.codigo} ({curso.nombre})")
                encontrado = True
        if not encontrado:
            print("  - Ningún curso encontrado con esa política de acceso.")

    def verificar_autorizacion(self, codigo_alumno, nombre_servidor, nombre_servicio):
        """Verifica si un alumno está autorizado para usar un servicio."""
        for curso in self.cursos.values():
            if str(codigo_alumno) in curso.alumnos and \
               curso.estado == 'DICTANDO' and \
               nombre_servidor in curso.servidores_politicas and \
               nombre_servicio in curso.servidores_politicas[nombre_servidor]:
                return True
        return False

def imprimir_menu_principal():
    print("\n##################################################")
    print("#     Network Policy manager de la UPSM        #")
    print("##################################################")
    print("Seleccione una opción:")
    print("1) Importar datos desde YAML (*)")
    print("2) Gestionar Cursos (*)")
    print("3) Gestionar Alumnos (*)")
    print("4) Gestionar Servidores (*)")
    print("5) Gestionar Conexiones (*)")
    print("6) Salir")

def menu(manager):
    while True:
        imprimir_menu_principal()
        opcion = input(">>> ").strip()
        if opcion == '1':
            filename = input("Ingrese el nombre del archivo YAML (ej: database.yaml): ").strip()
            manager.importar_datos(filename)
        elif opcion == '2':
            menu_cursos(manager)
        elif opcion == '3':
            menu_alumnos(manager)
        elif opcion == '4':
            menu_servidores(manager)
        elif opcion == '5':
            menu_conexiones(manager)
        elif opcion == '6':
            print("Saliendo de la aplicación.")
            sys.exit(0)
        else:
            print("Opción no válida. Intente de nuevo.")

def menu_cursos(manager):
    while True:
        print("\n--- Menú Cursos ---")
        print("1) Listar cursos (*)")
        print("2) Mostrar detalle de curso (*)")
        print("3) Actualizar curso (agregar/eliminar alumno) (*)")
        print("4) Volver al menú principal")
        opcion = input(">>> ").strip()
        if opcion == '1':
            manager.listar_cursos()
        elif opcion == '2':
            codigo = input("Ingrese el código del curso: ").strip()
            manager.mostrar_detalle_curso(codigo)
        elif opcion == '3':
            codigo = input("Ingrese el código del curso a actualizar: ").strip()
            manager.actualizar_curso(codigo)
        elif opcion == '4':
            break
        else:
            print("Opción no válida.")

def menu_alumnos(manager):
    while True:
        print("\n--- Menú Alumnos ---")
        print("1) Listar todos los alumnos (*)")
        print("2) Listar alumnos por curso (*)")
        print("3) Agregar nuevo alumno (*)")
        print("4) Volver al menú principal")
        opcion = input(">>> ").strip()
        if opcion == '1':
            manager.listar_alumnos()
        elif opcion == '2':
            codigo_curso = input("Ingrese el código del curso para filtrar: ").strip()
            manager.listar_alumnos(filtro_curso=codigo_curso)
        elif opcion == '3':
            codigo = input("Ingrese el código del nuevo alumno: ").strip()
            nombre = input("Ingrese el nombre del nuevo alumno: ").strip()
            mac = input("Ingrese la MAC del nuevo alumno: ").strip()
            manager.agregar_alumno(codigo, nombre, mac)
        elif opcion == '4':
            break
        else:
            print("Opción no válida.")


def menu_servidores(manager):
    while True:
        print("\n--- Menú Servidores ---")
        print("1) Listar servidores (*)")
        print("2) Mostrar detalle de servidor (*)")
        print("3) Listar cursos con acceso a un servicio (*)")
        print("4) Volver al menú principal")
        opcion = input(">>> ").strip()
        if opcion == '1':
            manager.listar_servidores()
        elif opcion == '2':
            nombre = input("Ingrese el nombre del servidor: ").strip()
            manager.mostrar_detalle_servidor(nombre)
        elif opcion == '3':
            nom_servidor = input("Ingrese el nombre del servidor: ").strip()
            nom_servicio = input("Ingrese el nombre del servicio: ").strip()
            manager.listar_cursos_por_servicio(nom_servidor, nom_servicio)
        elif opcion == '4':
            break
        else:
            print("Opción no válida.")

def menu_conexiones(manager):
    while True:
        print("\n--- Menú Conexiones ---")
        print("1) Crear conexión (*)")
        print("2) Listar conexiones (*)")
        print("3) Borrar conexión (*)")
        print("4) Volver al menú principal")
        opcion = input(">>> ").strip()
        if opcion == '1':
            cod_alumno = input("Ingrese el código del alumno: ").strip()
            nom_servidor = input("Ingrese el nombre del servidor: ").strip()
            nom_servicio = input("Ingrese el nombre del servicio (ej: ssh, web): ").strip()
            manager.crear_conexion(cod_alumno, nom_servidor, nom_servicio)
        elif opcion == '2':
            manager.listar_conexiones()
        elif opcion == '3':
            handler = input("Ingrese el handler de la conexión a borrar: ").strip()
            manager.borrar_conexion(handler)
        elif opcion == '4':
            break
        else:
            print("Opción no válida.")

def main():
    """Función principal que inicia la aplicación."""
    print("Iniciando Gestor de Políticas de Red...")
    if not FLOODLIGHT_ENABLED:
        print("************************************************************")
        print("*** ADVERTENCIA: La comunicación con Floodlight está       ***")
        print("*** desactivada. Todas las operaciones serán simuladas.    ***")
        print("*** Para activar, cambie FLOODLIGHT_ENABLED a True.        ***")
        print("************************************************************")
    
    manager = NetworkPolicyManager()
    #manager.importar_datos('datos.yaml')
    menu(manager)

if __name__ == "__main__":
    main()

