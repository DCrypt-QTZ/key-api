# Demo SAE Client code
# run to test Key Delivery API with list of SAE clients
# Note: for test purposes, all SAE clients are on same computer
# Note: SAE_ID is stored in client TLS cert (SubjectAltName URI)
#       client Alice's SAE_ID is 'DCrypt-QKD-Client-Alice' in TLS cert
#       and must match SAE_ID for client
import sae_client
import random
import os
import time

random.seed(os.urandom(32))

# trusted kme root ca (cert)
kme_server_ca = 'server-cert.pem'

saes = list()
clients = dict()
xport = 8080

# connect clients to kme server:port
# Alice   (connect to server localhost:8080)
sae_id   = 'DCrypt-QKD-Client-Alice'    # follow SAE_ID of TLS cert
saes.append(sae_id)
client = sae_client.sae_client(sae_id, kme_server_ca, 'certs/DCrypt-QKD-Client-Alice.pem')
clients[sae_id] = client
kme_addr = 'localhost'
kme_port = xport+0
if not client.connect2((kme_addr, kme_port)):
  print('ERROR: sae ' + sae_id + ' failed to connect to kme ' + kme_addr + ':' + str(kme_port))

# Bob   (connect to server localhost:8081)
sae_id   = 'DCrypt-QKD-Client-Bob'      # follow SAE_ID of TLS cert
saes.append(sae_id)
client = sae_client.sae_client(sae_id, kme_server_ca, 'certs/DCrypt-QKD-Client-Bob.pem')
clients[sae_id] = client
kme_addr = 'localhost'
kme_port = xport+1
if not client.connect2((kme_addr, kme_port)):
  print('ERROR: sae ' + sae_id + ' failed to connect to kme ' + kme_addr + ':' + str(kme_port))

# Charlie   (connect to server localhost:8082)
sae_id   = 'DCrypt-QKD-Client-Charlie'  # follow SAE_ID of TLS cert
saes.append(sae_id)
client = sae_client.sae_client(sae_id, kme_server_ca, 'certs/DCrypt-QKD-Client-Charlie.pem')
clients[sae_id] = client
kme_addr = 'localhost'
kme_port = xport+2
if not client.connect2((kme_addr, kme_port)):
  print('ERROR: sae ' + sae_id + ' failed to connect to kme ' + kme_addr + ':' + str(kme_port))

## Dora   (connect to server localhost:8083)
#sae_id   = 'DCrypt-QKD-Client-Dora'     # follow SAE_ID of TLS cert
#saes.append(sae_id)
#client = sae_client.sae_client(sae_id, kme_server_ca, 'certs/DCrypt-QKD-Client-Dora.pem')
#clients[sae_id] = client
#kme_addr = 'localhost'
#kme_port = xport+3
#if not client.connect2((kme_addr, kme_port)):
#  print('ERROR: sae ' + sae_id + ' failed to connect to kme ' + kme_addr + ':' + str(kme_port))

# print list of SAE_IDs
print(saes)




# get keys for random pair-wise connections between SAEs
for i in range(100):
  # wait 2s between requests
  print('')
  time.sleep(2.0)
  #
  print('KeyAPI test ' + str(i))
  sids = random.sample(saes, 2)   # pick any 2 sae clients
  it = iter(sids)
  sid1 = next(it)   # master sae
  sid2 = next(it)   # slave  sae
  print('  Master: ' + sid1)
  print('  Slave:  ' + sid2)
  client1 = clients[sid1]
  # master sae getkey request
  print('  master getkey')
  (status, keys) = client1.getkey(sid2, [], 256, 1)
  if status == 200:
    client2 = clients[sid2]
    kids = list()
    for kid in keys.keys():
      kids.append(kid)
    # slave sae getkeywid request
    print('  slave  getkeywid')
    (status, keys2) = client2.getkeywid(sid1, kids)
    if status == 200:
      print(keys)
      print(keys2)
      ok = True
      for kid in keys.keys():
        if (keys[kid] != keys2[kid]):
          print('  ERROR: mismatch for key id ' + kid)
          ok = False
      if ok:
        print('  OK: keys match')
    else:
      print('  ERROR: failed to getkey w id')
      print('  Keys: ' + str(kids))
    #
    print('  slave  getkeywid2')
    (status, keys3) = client2.getkeywid(sid1, kids)
    if status == 200:
      print('  ERROR: got key w id a second time!!')
      print('  Keys: ' + str(kids))
      print(keys)
      print(keys3)
  else:
    print('  ERROR: failed to getkey!')
  