from pwn import *
import time



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





def leer_coil(address, transaction_id, ip="127.0.0.1", port=502, unit_id=1):
    try:
        # Conectar
        conn = remote(ip, port, timeout=2)

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
        conn.close()

        # Validar tamaño mínimo esperado
        if len(response) < 10:
            raise ValueError("Respuesta demasiado corta.")

        # Extraer estado del coil
        data_byte = response[9]
        estado = (data_byte >> 0) & 0x01


        return "ON" if estado else "OFF"

    except Exception as e:
        return f"[ERROR] {e}"








def scan_coil_range(ip="127.0.0.1", port=502, unit_id=1, start_addr=0, end_addr=100):

    nCoils = 0
    avaliableCoils = []
    print(f"[+] Iniciando escaneo de coils en {ip}:{port} (unit_id={unit_id})")
    print(f"[+] Rango: {start_addr} a {end_addr}")

    for address in range(start_addr, end_addr + 1):
        try:
            conn = remote(ip, port, timeout=1)
            request = build_modbus_read_coils_request(
                transaction_id=address,  # podemos usar la dirección como ID
                unit_id=unit_id,
                start_address=address,
                quantity=1
            )
            conn.send(request)
            response = conn.recv(1024)
            conn.close()

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
