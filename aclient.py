import socket
import ssl
#import threading
#from threading import Lock

import logging as logg
import time         # sleep



##########################################################################################
# CLASS
##########################################################################################

class aclient:
  def __init__(self, cid, server_cafile='cert.pem', client_certfile=None):
    logg.getLogger().setLevel(logg.WARNING)
    self.client_id = cid
    self.connected = False
    self.server_cafile = server_cafile
    self.client_certfile = client_certfile
    self.info = 'Not connected'
    self.cert = None


  def connect2(self, server_addr):
    if self.connected:
      logg.error('client ' + self.client_id + ' already connected')
      return True
    else:
      self.info = 'server ' + server_addr[0] + ' port ' + str(server_addr[1])
      self.server_addr = server_addr
      return self.initConn()


  def initConn(self):
    self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    self.context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    self.context.load_verify_locations(self.server_cafile)
    if self.client_certfile:
      self.context.load_cert_chain(certfile=self.client_certfile)
    self.cert = None
    conn = None
    ok = False
    try:
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
      self.conn = self.context.wrap_socket(self.sock, server_hostname=self.server_addr[0])
      self.conn.connect(self.server_addr)
      # ok... server can reject client cert!
      # but we verified server, so we are happy....
      # we won't know server rejected us until we try to talk on connection?!?
      self.connected = True
      #
      self.cert = self.conn.getpeercert()
      self.cipher = self.conn.cipher()
      logg.warning('TLS connected to server ' + self.info + ' using ' + str(self.cipher))
      #
      #self.thread = threading.Thread(target=self.exec)
      #self.thread.start()
      ok = True
    except ssl.SSLError as e:
      logg.error('SSL ERR')
      logg.error('bad ' + self.info)
      logg.error(e)
      self.disconnect()
    except Exception as e:
      logg.error('bad ' + self.info)
      logg.error(e)
    #finally:
    #  self.connection.close()
    return ok


  # fake client action
  def exec(self):
    try:
      for i in range(10):
        time.sleep(1.0)
        tosend = self.client_id + ' hello hello ' + str(i)
        logg.info('send ' + str(len(tosend)))
        logg.debug(tosend)
        self.conn.send(tosend.encode())
        recv = self.conn.recv().decode()
        logg.info('recv ' + str(len(recv)))
        logg.debug(recv)
    finally:
      self.conn.close()
      self.connected = False
      logg.warning('disconnected from ' + self.info)
      self.cert = None
      
  # disconnect from server
  def disconnect(self):
    if self.connected:
      self.conn.close()
      self.connected = False
      logg.warning('disconnected from ' + self.info)
      self.cert = None
