# Demo KME Server code
# run only if using DCrypt KME server
import qkdnet
import kme_server
import random
import os

random.seed(os.urandom(32))

qkd = qkdnet.qkdnet()     # qkdnet object stores network info
kmes = qkd.createNodes(3) # 3 qkd nodes (random UUIDs)

servers = dict()
xport = 8080              # kme servers on localhost at ports 8080, 8081, 8082
port = xport
for kid in kmes:
  serve = kme_server.kme_server(kid, port, qkd, 64, 'server-combo.pem', 'certs/qkd.d-crypt.com.crt')
  servers[kid] = (('localhost', port), serve)
  port = port + 1

# print list of KME_IDs
kmes
