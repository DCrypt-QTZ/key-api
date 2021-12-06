D'Crypt demo Key Delivery API
=============================

To use both D'Crypt KME Server and SAE Client code:
1. Launch KME Server
  a. In terminal, execute "python3 launch_server.py"
     This will run KME server with 3 random KME_IDs on localhost ports 8080, 8081 & 8082
2. Launch SAE Clients
  b. In another terminal on same computer as KME server, execute "python3 launch_clients.py"
     This will run 3 SAE clients with SAE_IDs "DCrypt-QKD-Client-Alice", "DCrypt-QKD-Client-Bob" & "DCrypt-QKD-Client-Charlie"
     These 3 clients will connect to KME server "localhost" on ports 8080, 8081 & 8082 respectively
  c. Random "getkey()" (master SAE) and "getkeywid()" (slave SAE) commands will be executed between random pairs of SAEs
     "getkeywid()" will be called a second time for the slave SAE, to verify that the QKD keys have been removed after the first "getkeywid()"
     100 random pairs of master/slave SAE connections will be tried
     Note: client will not call "getstatus()" before requesting key, but "getstatus()" function is implemented


To use D'Crypt SAE Client code with your own KME server:
0. Modify your KME server code to accept D'Crypt SAE root CA
   certs/qkd.d-crypt.com.crt
1. Modify "launch_clients.py" file
   a. change line
        kme_server_ca = 'server-cert.pem'
      to point to KME root CA of your KME server
   b. for each SAE client, change lines
        kme_addr = 'localhost'
        kme_port = xport+0
      to point to server address & port of your KME server(s)
      D'Crypt SAE client will connect to any KME server with a recognized KME root CA
   Note: the SAE_IDs are also stored in the SAE TLS certificate; if you change the SAE_ID
     they will not match the SAE_ID stored in the TLS certificate
2. Launch SAE Clients
  b. In a terminal, execute "python3 launch_clients.py"
     This will run 3 SAE clients with SAE_IDs "DCrypt-QKD-Client-Alice", "DCrypt-QKD-Client-Bob" & "DCrypt-QKD-Client-Charlie"
     These 3 clients will connect to specified KME server(s)
  c. Random "getkey()" (master SAE) and "getkeywid()" (slave SAE) commands will be executed between random pairs of SAEs
     "getkeywid()" will be called a second time for the slave SAE, to verify that the QKD keys have been removed after the first "getkeywid()"
     100 random pairs of master/slave SAE connections will be tried
     Note: client will not call "getstatus()" before requesting key, but "getstatus()" function is implemented
  Note: Currently, "launch_clients.py" will run correctly only if all 3 clients are on the same computer
     because code calls "getkey()" and "getkeywid()" of the SAE clients directly (not remotely)
     However, the KME server(s) may all be located on different computers
  


Example SAE Client output:
  WARNING:root:TLS connected to server localhost port 8080 using ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
  WARNING:root:no KME ID in cert!
  WARNING:root:TLS connected to server localhost port 8081 using ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
  WARNING:root:no KME ID in cert!
  WARNING:root:TLS connected to server localhost port 8082 using ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
  WARNING:root:no KME ID in cert!
  ['DCrypt-QKD-Client-Alice', 'DCrypt-QKD-Client-Bob', 'DCrypt-QKD-Client-Charlie']
  KeyAPI test 0
    Master: DCrypt-QKD-Client-Alice
    Slave:  DCrypt-QKD-Client-Bob
    master getkey
    slave  getkeywid
  {'04b91bce-c639-cd7f-dd8a-77889f1256d0': 'Q/5CqTnqQEJJhQZTsOfvSdmuVLulrnwgapByv8zFwUw='}
  {'04b91bce-c639-cd7f-dd8a-77889f1256d0': 'Q/5CqTnqQEJJhQZTsOfvSdmuVLulrnwgapByv8zFwUw='}
    OK: keys match
    slave  getkeywid2

  KeyAPI test 1
    Master: DCrypt-QKD-Client-Charlie
    Slave:  DCrypt-QKD-Client-Alice
    master getkey
    slave  getkeywid
  {'14ab301e-7cc1-84c0-1717-b5a0cc1f9a15': 'W1qhHN5VRp0QdnR7xIKKDvVRI8DAAAEYMnBbTWtefp0='}
  {'14ab301e-7cc1-84c0-1717-b5a0cc1f9a15': 'W1qhHN5VRp0QdnR7xIKKDvVRI8DAAAEYMnBbTWtefp0='}
    OK: keys match
    slave  getkeywid2



Files include:

KME Server code:
  qkdnet.py             # code to store QKD network & client information
  aserver.py            # generic TLS server code
  kme_server.py         # KME server code
  launch_server.py      # top-level code for launching D'Crypt KME server

KME Server certs:
  server-key.pem        # un-encrypted KME server private key (2048b RSA key)
  server-cert.pem       # KME server TLS certificate
  server-combo.pem      # KME server private key + TLS cert (as required by Python ssl)
 
SAE Client code:
  aclient.py            # generic TLS client code
  sae_client.py         # SAE client code
  launch_clients.py     # top-level code for launching D'Crypt SAE clients
  
SAE Client certs:
  certs/qkd.d-crypt.com.crt                 # SAE client root CA certificate (384b ECC)
  certs/alice.client.qkd.d-crypt.com.raw    # Alice   SAE private key (384b ECC key)
  certs/alice.client.qkd.d-crypt.com.crt    # Alice   SAE TLS certificate
  certs/DCrypt-QKD-Client-Alice.pem         # Alice   SAE private key + TLC cert (as required by Python ssl)
  certs/bob.client.qkd.d-crypt.com.raw      # Bob     SAE private key (384b ECC key)
  certs/bob.client.qkd.d-crypt.com.crt      # Bob     SAE TLS certificate
  certs/DCrypt-QKD-Client-Bob.pem           # Bob     SAE private key + TLC cert (as required by Python ssl)
  certs/charlie.client.qkd.d-crypt.com.raw  # Charlie SAE private key (3072b RSA key)
  certs/charlie.client.qkd.d-crypt.com.crt  # Charlie SAE TLS certificate
  certs/DCrypt-QKD-Client-Charlie.pem       # Charlie SAE private key + TLC cert (as required by Python ssl)
