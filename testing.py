from functions import *

conn = connection()

# Escritura
escribir_coil(conn, 16, "on", 1)
escribir_coil(conn, 36, "on", 1)
escribir_coil(conn, 52, "on", 1)
escribir_coil(conn, 78, "on", 1)


# Lectura
print(leer_coil(conn, 16,1))
print(leer_coil(conn, 36,1))
print(leer_coil(conn, 52, 1))
print(leer_coil(conn, 78, 1))


conn.close()