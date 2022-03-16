import aclient
import logging as logg

import urllib.parse as parse
import json


##########################################################################################
# CLASS
##########################################################################################

class sae_client(aclient.aclient):

  admin_api_path = '/api/v1/admin/'
  register_path  = 'reg_sae'
  key_api_path = '/api/v1/keys/'
  status_path  = '/status'
  getkey_path  = '/enc_keys'
  getkwid_path = '/dec_keys'
  http_ver     = 'HTTP/1.1'
  #
  key_size_kw   = 'size'
  num_keys_kw   = 'number'
  xtra_sae_kw   = 'additional_slave_SAE_IDs'
  mst_sae_kw    = 'master_SAE_ID'
  content_kw    = 'Content-Type:'
  accept_kw     = 'Accept:'
  json_kw       = 'application/json'
  key_id_kw     = 'key_ID'
  key_ids_kw    = 'key_IDs'
  key_kw        = 'key'
  keys_kw       = 'keys'


  def __init__(self, cid, server_cafile='server-cert.pem', client_combofile='client-combo.pem'):
    # should check SAE_ID in our own tls cert...
    super().__init__(cid, server_cafile, client_combofile)

  # check SAE_ID in our own cert here
  def getSelfID(cert):
    sae_ids = list()
    if cert:
      try:
        SAN = cert['subjectAltName']
        for (kind, value) in SAN:
          if kind == 'URI':
            uri = value
            x = uri.split(':',1)
            scheme = x[0]
            if scheme == 'SAE_ID':
              path = x[1]
              sae_ids.append(path)
      except:
        None
    return sae_ids

  # check KME_ID in KME cert here
  def getID(self, cert):
    kme_ids = list()
    if cert:
      try:
        SAN = cert['subjectAltName']
        for (kind, value) in SAN:
          if kind == 'URI':
            uri = value
            x = uri.split(':',1)
            scheme = x[0]
            if scheme == 'KME_ID':
              path = x[1]
              kme_ids.append(path)
      except:
        None
    return kme_ids


  # function to register with kme server
  # tell kme our sae_id
  # client gets kme_id
  #
  # Extension to Key Delivery API!
  # NOT STANDARD!
  def register(self):
    status = 400
    self.kme_id = None
    try:
      sae_id = self.client_id
      fmt = 'POST'
      params = dict()
      params[self.mst_sae_kw] = sae_id
      url = self.admin_api_path + self.register_path
      tosend = self.genCmd(fmt, url, params)
      logg.info('send ' + str(len(tosend)))
      logg.debug(tosend)
      self.conn.send(tosend.encode())
      recv = self.conn.recv().decode()
      logg.info('recv ' + str(len(recv)))
      logg.debug(recv)
    except Exception as e:
      logg.error('register: ' + fmt + ' ' + url + ' ' + str(params))
      logg.error('KME: ' + self.info)
      logg.error(e)
    return (status, self.kme_id)


  # connect to server
  # we check for KME_ID in cert here
  def initConn(self):
    ok = super().initConn()
    self.kme_id = None
    if not ok:
      return ok
    #
    ok = False
    kme_ids = self.getID(self.cert)
    lid = len(kme_ids)
    if lid == 0:
      errmsg = 'no KME ID in cert!'
      # we don't care...
      ok = True
    elif lid > 1:
      errmsg = '>1 KME ID in cert! ' + str(kme_ids)
    else:
      self.kme_id = kme_ids[0]
      errmsg = 'registered to KME ID ' + self.kme_id
      ok = True
    logg.warning(errmsg)
    return ok


  # ask kme server for status
  # tell slave_sae_id
  # receive status
  def getstatus(self, sae_id):
    status = 400
    kme_status = None
    try:
      fmt = 'GET'
      params = dict()
      url = self.key_api_path + sae_id + self.status_path
      tosend = self.genCmd(fmt, url, params)
      logg.info('send ' + str(len(tosend)))
      logg.debug(tosend)
      self.conn.send(tosend.encode())
      recv = self.conn.recv().decode()
      logg.info('recv ' + str(len(recv)))
      logg.debug(recv)
      #
      (status, errmsg, params) = self.decode(recv)
      logg.info(str(status) + ' ' + errmsg)
      if status == 200:
        kme_status = params
    except Exception as e:
      logg.error('getstatus: ' + fmt + ' ' + url + ' ' + str(params))
      logg.error('KME: ' + self.info)
      logg.error(e)
    return (status, kme_status)


  # ask kme server for key
  # tell size, num_keys, slave_sae_id(s)
  # receive key(s)
  def getkey(self, sae_id, peers=list(), bits=256, nkey=1):
    assert bits >= 64,   'Too few key bits'
    assert bits <= 1024, 'Too many key bits'
    assert nkey >= 1,    'Too few number of keys'
    assert nkey <= 16,   'Too many number of keys'
    status = 400
    keys = dict()
    try:
      if peers:
        fmt = 'POST'
      else:
        fmt = 'GET'
      params = dict()
      params[self.key_size_kw] = bits
      if nkey > 1:
        params[self.num_keys_kw] = nkey
      if peers:
        params[self.xtra_sae_kw] = peers
      url = self.key_api_path + sae_id + self.getkey_path
      tosend = self.genCmd(fmt, url, params)
      logg.info('send ' + str(len(tosend)))
      logg.debug(tosend)
      self.conn.send(tosend.encode())
      recv = self.conn.recv().decode()
      logg.info('recv ' + str(len(recv)))
      logg.debug(recv)
      #
      (status, errmsg, params) = self.decode(recv)
      logg.info(str(status) + ' ' + errmsg)
      if status == 200:
        keyl = params.get(self.keys_kw, None)
        if keyl:
          for item in keyl:
            keyid  = item.get(self.key_id_kw, None)
            keyval = item.get(self.key_kw, None)
            if keyid and keyval:
              keys[keyid] = keyval
    except Exception as e:
      logg.error('getkey: ' + fmt + ' ' + url + ' ' + str(params))
      logg.error('KME: ' + self.info)
      logg.error(e)
    return (status, keys)

  
  # ask kme server for key
  # tell size, num_keys, slave_sae_id(s)
  # receive key(s)
  def getkeywid(self, sae_id, kids):
    status = 400
    keys = dict()
    try:
      params = dict()
      if len(kids) > 1:
        fmt = 'POST'
        klist = list()
        for kid in kids:
          kval = {self.key_id_kw:kid}
          klist.append(kval)
        params[self.key_ids_kw] = klist
      else:
        fmt = 'GET'
        params[self.key_id_kw] = next(iter(kids))
      url = self.key_api_path + sae_id + self.getkwid_path
      tosend = self.genCmd(fmt, url, params)
      logg.info('send ' + str(len(tosend)))
      logg.debug(tosend)
      self.conn.send(tosend.encode())
      recv = self.conn.recv().decode()
      logg.info('recv ' + str(len(recv)))
      logg.debug(recv)
      #
      (status, errmsg, params) = self.decode(recv)
      logg.info(str(status) + ' ' + errmsg)
      if status == 200:
        keyl = params.get(self.keys_kw, None)
        if keyl:
          for item in keyl:
            keyid  = item.get(self.key_id_kw, None)
            keyval = item.get(self.key_kw, None)
            if keyid and keyval:
              keys[keyid] = keyval
    except Exception as e:
      logg.error('getkeywid: ' + fmt + ' ' + url + ' ' + str(params))
      logg.error('KME: ' + self.info)
      logg.error(e)
    return (status, keys)

  
  # pack params in query (GET)
  # or as json (POST)
  def genCmd(self, fmt, url, params):
    url  = parse.quote(url)
    args = ''
    if fmt == 'GET':
      if params:
        for itempr in params.items():
          args += '&' + parse.quote_plus(itempr[0]) + '=' + parse.quote_plus(str(itempr[1]))
        args  = '?' + args[1:]    # skip leading &
    elif fmt == 'POST':
      args  = json.dumps(params)
    #
    tosend  = fmt + ' ' + url
    if fmt == 'GET':
      tosend += args
    tosend += ' ' + self.http_ver + '\r\n'
    if fmt == 'POST':
      tosend += self.content_kw + ' ' + self.json_kw + '\r\n'
    # Host header is REQUIRED; host is server addr/port
    tosend += 'Host: ' + self.server_addr[0] + ':' + str(self.server_addr[1]) + '\r\n'   # Host
    tosend += self.accept_kw + ' ' + self.json_kw + '\r\n'      # Accept
    tosend += '\r\n'
    if fmt == 'POST':
      tosend += args
    return tosend


  def decode(self, recv):
    status = 404
    errmsg = ''
    params = dict()
    try:
      x = recv.split('\n', 1)
      x[0] = x[0].rstrip()
      y = x[0].split(' ', 2)
      status = int(y[1])
      errmsg = y[2]
      if status == 200:
        # look for Content-Type: application/json
        (isjson, remainder) = self.hasHeader(x[1], self.content_kw, self.json_kw)
        params = json.loads(remainder)
    except Exception as e:
      logg.error('Decoding ' + recv)
      logg.error(e)
    return (status, errmsg, params)


  # read until empty line
  def hasHeader(self, recv, aname, aval):
    found = False
    while True:
      x = recv.split('\n', 1)
      x[0] = x[0].rstrip()
      if len(x) > 1:
        recv = x[1]
      else:
        recv = ''
      if x[0]:
        # name should be case insensitive, but value is sensitive...
        pos1 = x[0].lower().find(aname.lower())
        pos2 = x[0].find(aval)
        if pos1>0 and pos2>0 and (pos2>pos1):
          found = True
      else:
        return (found, recv)


  # disconnect from server
  def disconnect(self):
    self.kme_id = None
    super().disconnect()
