from pwn import *
import time


def connection(ip="127.0.0.1", port=502):

    try:
        conn = remote(ip, port, timeout=2)

    except Exception as e:
        return f"Error de conexión: {e}"


    return conn



def build_modbus_read_coils_request(transaction_id, unit_id, start_address, quantity):
    
    # Valores por defecto
    protocol_id = p16(0x0000, endianness='big')  # Modbus TCP protocol ID = 0
    length = p16(0x0006, endianness='big')  # Longitud del PDU (función + 2x16 bits)
    function_code = p8(0x01)  # 0x01 = Read Coils

    # Codificación de los parametros
    transaction_id = p16(transaction_id, endianness='big')
    unit_id = p8(unit_id)
    start_address = p16(start_address, endianness='big')
    quantity = p16(quantity, endianness='big')
    
    header = transaction_id + protocol_id + length + unit_id
    data = start_address + quantity


    return header + function_code + data





def leer_coil(conn, address, transaction_id, ip="127.0.0.1", port=502, unit_id=1):
    try:
        # Crear solicitud
        request = build_modbus_read_coils_request(
            transaction_id=transaction_id,
            unit_id=unit_id,
            start_address=address,
            quantity=1
        )

        # Enviar y recibir
        conn.send(request)
        response = conn.recv(1024)
        

        # Validar tamaño mínimo esperado
        if len(response) < 10:
            raise ValueError("Respuesta demasiado corta.")

        # Extraer estado del coil
        data_byte = response[9]
        estado = (data_byte >> 0) & 0x01


        return "ON" if estado else "OFF"

    except Exception as e:
        return f"[ERROR] {e}"





def build_modbus_write_single_coil_request(transaction_id, unit_id, address, estado):
    protocol_id = 0
    length = 6  # unit_id + function_code + address + value = 1 + 1 + 2 + 2
    function_code = 5  # Write Single Coil

    # Valor a escribir (0xFF00 = ON, 0x0000 = OFF)
    value = 0xFF00 if estado.upper() == "ON" else 0x0000

    request = (
        p16(transaction_id, endianness='big') +
        p16(protocol_id, endianness='big') +
        p16(length, endianness='big') +
        p8(unit_id) +
        p8(function_code) +
        p16(address, endianness='big') +
        p16(value, endianness='big')
    )

    return request



def escribir_coil(conn, address, estado, transaction_id=1, ip="127.0.0.1", port=502, unit_id=1):

    try:

        # Crear solicitud
        request = build_modbus_write_single_coil_request(
            transaction_id=transaction_id,
            unit_id=unit_id,
            address=address,
            estado=estado
        )

        # Enviar y recibir
        conn.send(request)
        response = conn.recv(1024)
        

        # Validar que el servidor respondió correctamente
        if response[7] != 5:  # function code
            raise ValueError(f"Código de función inesperado: {response[7]}")

        return f"Coil {address} escrito a '{estado.upper()}' correctamente."

    except Exception as e:
        return f"[ERROR] {e}"






def scan_coil_range(conn, ip="127.0.0.1", port=502, unit_id=1, start_addr=0, end_addr=100):

    nCoils = 0
    avaliableCoils = []
    print(f"[+] Iniciando escaneo de coils en {ip}:{port} (unit_id={unit_id})")
    print(f"[+] Rango: {start_addr} a {end_addr}")

    for address in range(start_addr, end_addr + 1):
        try:
            request = build_modbus_read_coils_request(
                transaction_id=address,  # podemos usar la dirección como ID
                unit_id=unit_id,
                start_address=address,
                quantity=1
            )
            conn.send(request)
            response = conn.recv(1024)
            

            if len(response) >= 9:
                function_code = response[7]
                if function_code == 0x01:
                    byte_count = response[8]
                    data = response[9:9 + byte_count]
                    coil_state = "ON" if data[0] & 0x01 else "OFF"
                    print(f"[✔] Coil {address:05d} válido – Estado: {coil_state}")
                    nCoils += 1
                    avaliableCoils.append((address, coil_state))
                elif function_code & 0x80:
                    exception_code = response[8]
                    print(f"[✘] Coil {address:05d} inválido – Excepción Modbus: 0x{exception_code:02X}")
                else:
                    print(f"[?] Coil {address:05d} – Respuesta desconocida")
            else:
                print(f"[!] Coil {address:05d} – Respuesta muy corta")

            time.sleep(0.05)  # espera


        except Exception as e:
            print(f"[ERROR] Coil {address:05d} – {e}")


    print(f"\n\nEXISTEN {nCoils} disponibles")
    for coil in avaliableCoils:
        coil_address, coil_state = coil
        print("*******************************")
        print(f"Coil Addres: {coil_address}")
        print(f"Coil State: {coil_state}")




def build_modbus_read_holding_registers_request(transaction_id, unit_id, start_address, quantity):
    protocol_id = 0
    length = 6  # unit_id + function_code + start_address (2) + quantity (2)
    function_code = 0x03  # Read Holding Registers

    request = (
            p16(transaction_id, endianness='big') +
            p16(protocol_id, endianness='big') +
            p16(length, endianness='big') +
            p8(unit_id) +
            p8(function_code) +
            p16(start_address, endianness='big') +
            p16(quantity, endianness='big')
    )
    return request


def escanear_holding_registers(ip="127.0.0.1", port=502, unit_id=1, rango=(0, 200)):

    print(f"[🔍] Escaneando holding registers en {ip}:{port} (unit_id={unit_id})...")
    holdingRegisters = []
    for address in range(rango[0], rango[1]):
        try:
            conn = remote(ip, port, timeout=1)

            transaction_id = address  # uno distinto por cada petición
            request = build_modbus_read_holding_registers_request(
                transaction_id=transaction_id,
                unit_id=unit_id,
                start_address=address,
                quantity=1
            )

            conn.send(request)
            response = conn.recv(1024)
            conn.close()

            # Verificar si la respuesta es válida
            if len(response) >= 11 and response[7] == 0x03:
                data_bytes = response[9:11]
                valor = u16(data_bytes, endianness='big')
                print(f"[✔] Dirección {address:05d}: valor = {valor}")
                holdingRegisters.append((address, valor))
            else:
                print(f"[✘] Dirección {address:05d}: sin respuesta válida")

        except Exception as e:
            print(f"[!] Dirección {address:05d}: error ({e})")


    return holdingRegisters



def build_modbus_ping_request(transaction_id, unit_id):
    protocol_id = 0
    length = 6  # unit_id + function_code + start_address (2) + quantity (2)
    function_code = 0x03  # Intentamos leer 1 holding register (funciona como "ping")
    start_address = 0
    quantity = 1

    request = (
        p16(transaction_id, endian='big') +
        p16(protocol_id, endian='big') +
        p16(length, endian='big') +
        p8(unit_id) +
        p8(function_code) +
        p16(start_address, endian='big') +
        p16(quantity, endian='big')
    )
    return request



def escanear_unit_ids(ip="127.0.0.1", port=502, rango=(1, 248)):
    print(f"[🔍] Escaneando Unit IDs válidos en {ip}:{port}...")
    unit_ids_validos = []

    for unit_id in range(rango[0], rango[1] + 1):
        try:
            conn = remote(ip, port, timeout=1)

            transaction_id = unit_id
            request = build_modbus_ping_request(transaction_id, unit_id)
            conn.send(request)
            response = conn.recv(1024)
            conn.close()

            if len(response) >= 9 and response[7] == 0x03:
                print(f"[✔] Unit ID {unit_id:03d} RESPONDE.")
                unit_ids_validos.append(unit_id)
            else:
                print(f"[✘] Unit ID {unit_id:03d} sin respuesta válida.")

        except Exception:
            print(f"[ ] Unit ID {unit_id:03d} sin respuesta (timeout o error)")

    return unit_ids_validos


