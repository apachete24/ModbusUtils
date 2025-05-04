from functions import *

conn = connection()

for i in range(1, 400):
    escribir_coil(conn, address=i, estado="ON", unit_id=25)

scan_coil_range(conn, unit_id=25, end_addr=400)

conn.close()