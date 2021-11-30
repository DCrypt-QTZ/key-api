import socket
import ssl
import threading
from threading import Lock

import logging as logg



def getinfo(client_addr):
  info = 'client ' + client_addr[0] + ' port ' + str(client_addr[1])
  return info


##########################################################################################
# CLASS
##########################################################################################

class aserver:
  def __init__(self, sid, port, maxconn=64, server_certfile='combo.pem', client_cafile=None):
    logg.getLogger().setLevel(logg.WARNING)
    self.server_id = sid
    self.server_certfile = server_certfile
    self.client_cafile = client_cafile
    #
    self.server_addr = ('0.0.0.0', port)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    self.sock.bind(self.server_addr)        # this will THROW if port is in use!
    self.sock.listen(maxconn)
    logg.warning('server ' + sid + ' listening on ' + self.server_addr[0] + ' port ' + str(port))
    #
    self.conn_mutex = Lock()
    self.conns = dict()
    self.maint = threading.Thread(target=self.listen)
    self.maint.start()


  def regCert(self, cert, conn):
    return True


  # global listener
  # spawns new thread per connection
  def listen(self):
    done = False
    while not done:
      try:
        # listen for incoming connections
        csock, client_addr = self.sock.accept()
        info = getinfo(client_addr)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.load_cert_chain(self.server_certfile)
        if self.client_cafile:
          context.verify_mode = ssl.CERT_REQUIRED
          context.load_verify_locations(self.client_cafile)
        #context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
        # this can throw (cert verf error)
        conn = context.wrap_socket(csock, server_side=True)
        #
        client_cert = conn.getpeercert()
        cipher = conn.cipher()
        logg.warning('TLS connected to client ' + info + ' using ' + str(cipher))
        ok = self.regCert(client_cert, conn)
        if ok:
          mt = threading.Thread(target=self.serve, args=(conn,))
          self.conn_mutex.acquire()
          self.conns[conn] = client_addr
          self.conn_mutex.release()
          mt.start()
          logg.warning('KME added ' + info)
        else:
          # sae_id rejected
          logg.warning('KME rejected ' + info)
          conn.close()
      except ssl.SSLError as e:
        csock.close()
        logg.error('bad ' + info)
        logg.error(e)
      except KeyboardInterrupt:
        done = True
        logg.warning('Key interrupt; breaking out of server loop')
        self.conn_mutex.acquire()
        myconns = self.conns.keys()
        self.conn_mutex.release()
        for con in myconns:
          self.disconnect(con)
  

  # per connection server (per thread)
  def serve(self, conn):
    done = False
    while not done:
      try:
        recv = conn.recv().decode()
        if recv:
          logg.info('received ' + str(len(recv)))
          logg.debug(recv)
          retval = self.server_response(recv, conn)
          conn.write(retval.encode())
          logg.info('returned ' + str(len(retval)))
          logg.debug(retval)
        else:
          logg.info('conn terminated')
          done = True
      except ssl.SSLError as e:
        # ssl error, quit serving connection...
        logg.error('SSL ERR')
        self.conn_mutex.acquire()
        info = getinfo(self.conns[conn])
        self.conn_mutex.release()
        logg.error(info)
        logg.error(e)
        done = True
      except Exception as msg:
        # other exception, keep going?
        self.conn_mutex.acquire()
        info = getinfo(self.conns[conn])
        self.conn_mutex.release()
        logg.error(info)
        logg.error(msg)
    self.disconnect(conn)


  def server_response(self, recv, conn):
    retval = recv
    return retval
    
  
  def disconnect(self, conn):
    conn.close()
    self.conn_mutex.acquire()
    client_addr = self.conns.pop(conn)
    info = getinfo(client_addr)
    self.conn_mutex.release()
    logg.warning('close ' + info)
