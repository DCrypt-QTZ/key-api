import aserver
import logging as logg
from threading import Lock

import urllib.parse as parse
import json

import qkdnet




##########################################################################################
# CLASS
##########################################################################################

class kme_server(aserver.aserver):

  content_kw    = 'Content-Type:'
  accept_kw     = 'Accept:'
  json_kw       = 'application/json'
  #
  admin_api_path = '/api/v1/admin/'
  register_path  = 'reg_sae'
  key_api_path = '/api/v1/keys/'
  status_path  = 'status'
  getkey_path  = 'enc_keys'
  getkwid_path = 'dec_keys'
  http_ver     = 'HTTP/1.1'
  #
  key_size_kw   = 'size'
  num_keys_kw   = 'number'
  xtra_sae_kw   = 'additional_slave_SAE_IDs'
  mst_sae_kw    = 'master_SAE_ID'
  slv_sae_kw    = 'slave_SAE_ID'
  src_kme_kw    = 'source_KME_ID'
  tgt_kme_kw    = 'target_KME_ID'
  key_sz_kw     = 'key_size'
  key_ct_kw     = 'stored_key_count'
  key_mct_kw    = 'max_key_count'
  key_mreq_kw   = 'max_key_per_request'
  key_max_kw    = 'max_key_size'
  key_min_kw    = 'min_key_size'
  max_sae_ct    = 'max_SAE_ID_count'
  keys_kw       = 'keys'
  key_kw        = 'key'
  key_id_kw     = 'key_ID'
  key_ids_kw    = 'key_IDs'
  #
  


  def __init__(self, sid, port, qkdinfo, maxconn=64, server_certfile='server-combo.pem', client_cafile='client-cert.pem'):
    # add our own tracking data
    self.qkdnet = qkdinfo     # this has own mutex!
    #
    self.sae_mutex = Lock()
    self.conn2sae = dict()
    #
    super().__init__(sid, port, maxconn, server_certfile, client_cafile)


  # check SAE_ID in cert here
  def getID(self, cert):
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

  # map connection to sae_id
  def regCert(self, cert, conn):
    sae_ids = self.getID(cert)
    lid = len(sae_ids)
    ok = False
    if lid == 0:
      errmsg = 'no SAE ID in cert!'
    elif lid > 1:
      errmsg = '>1 SAE ID in cert! ' + str(sae_ids)
    else:
      sae_id = sae_ids.pop()
      self.sae_mutex.acquire()
      exist = self.conn2sae.get(conn, None)
      if not exist:
        self.conn2sae[conn] = sae_id
        self.qkdnet.regSAE(self.server_id, sae_id)
        errmsg = 'registered SAE ID ' + sae_id + ' to connection'
        ok = True
      else:
        errmsg = 'SAE ID ' + sae_id + ' already registered!'
      self.sae_mutex.release()
    logg.warning(errmsg)
    return ok


  def decode(self, recv):
    url = ''
    params = dict()
    retval = ''
    try:
      x = recv.split('\n', 1)
      x[0] = x[0].rstrip()
      y = x[0].split(' ')
      z = y[1].split('?', 1)
      url = parse.unquote(z[0])
      fmt = y[0]
      if fmt == 'GET' and len(z) > 1:
        args = z[1].split('&')
        for argpr in args:
          aa = argpr.split('=', 1)
          params[aa[0]] = aa[1]
          try:
            params[aa[0]] = int(aa[1])    # for integer params...
          except:
            None
      elif fmt == 'POST':
        # look for Content-Type: application/json
        (isjson, remainder) = self.hasHeader(x[1], self.content_kw, self.json_kw)
        params = json.loads(remainder)
    except Exception as e:
      logg.error('Decoding ' + recv)
      logg.error(e)
    return (url, params)
  
  
  # read until empty line
  def hasHeader(self, recv, aname, aval):
    found = False
    while True:
      x = recv.split('\n', 1)
      x[0] = x[0].rstrip()
      if len(x) > 1 and x[1]:
        recv = x[1]
      else:
        recv = ''
      if x[0]:
        # name should be case insensitive, but value is sensitive...
        pos1 = x[0].lower().find(aname.lower())
        pos2 = x[0].find(aval)
        if pos1>=0 and pos2>=0 and (pos2>pos1):
          found = True
      else:
        return (found, recv)


  def server_response(self, recv, conn):
    retval = '503 Internal Server Error\r\n'
    (url, params) = self.decode(recv)
    pos = url.find(self.key_api_path)
    if pos >= 0:
      x = url.split(self.key_api_path, 1)
      alen = len(x)
      y = x[alen-1].split('/')
      sae_id = y[0]
      cmd    = y[1]
      if   cmd == self.getkey_path:
        retval = self.getkey(sae_id, params, conn)
      elif cmd == self.getkwid_path:
        retval = self.getkeywid(sae_id, params, conn)
      elif cmd == self.status_path:
        retval = self.getstatus(sae_id, params, conn)
    else:
      pos = url.find(self.admin_api_path)
      if pos >= 0:
        x = url.split(self.admin_api_path, 1)
        y = x[1].split('/')
        cmd = y[0]
        if  cmd == self.register_path:
          retval = self.admreg(params, conn)
    
    retval = self.http_ver + ' ' + retval
    return retval


  def admreg(self, params, conn):
    logg.info('admreg')
    status = 400
    errmsg = ''
    rparams = dict()
    try:
      sae_id = params[self.mst_sae_kw]
      self.sae_mutex.acquire()
      exist = self.conn2sae.get(conn, None)
      if not exist:
        self.conn2sae[conn] = sae_id
        self.qkdnet.regSAE(self.server_id, sae_id)
        status = 200
        errmsg = 'OK'
        logg.warning('registered sae_id ' + sae_id + ' to connection')
      else:
        errmsg = 'Connection already registered'
      self.sae_mutex.release()
    except:
      errmsg = 'Missing ' + self.mst_sae_kw
    #
    if status == 200:
      rparams[self.src_kme_kw] = self.server_id    
    return self.genResp(status, errmsg, rparams)
    
    
  def getstatus(self, sae_id, params, conn):
    logg.info('getstatus')
    status = 503
    errmsg = ''
    rparams = dict()
    try:
      self.sae_mutex.acquire()
      msae_id = self.conn2sae.get(conn, None)
      self.sae_mutex.release()
      if msae_id:
        tgt_kme_id = self.qkdnet.saetokme(sae_id)
        if tgt_kme_id:
          status = 200
          errmsg = 'OK'
        else:
          errmsg = 'Unable to find kme_id of slave sae_id'
      else:
        errmsg = 'Master sae_id for connection not found'
    except:
      errmsg = 'Unknown error'
    #
    if status == 200:
      rparams[self.src_kme_kw] = self.server_id
      rparams[self.tgt_kme_kw] = tgt_kme_id
      rparams[self.mst_sae_kw] = msae_id
      rparams[self.slv_sae_kw] = sae_id
      rparams[self.key_sz_kw]  = 256
      rparams[self.key_ct_kw]  = 12345
      rparams[self.key_mct_kw] = 1000000
      rparams[self.key_mreq_kw] = 16
      rparams[self.key_max_kw] = 1024
      rparams[self.key_min_kw] = 64
      rparams[self.max_sae_ct] = 0
    return self.genResp(status, errmsg, rparams)
    
  
  def getkey(self, sae_id, params, conn):
    logg.info('getkey')
    status = 503
    errmsg = ''
    rparams = dict()
    try:
      self.sae_mutex.acquire()
      msae_id = self.conn2sae.get(conn, None)
      self.sae_mutex.release()
      if msae_id:
        tgt_kme_id = self.qkdnet.saetokme(sae_id)
        if tgt_kme_id:
          status = 200
          errmsg = 'OK'
        else:
          errmsg = 'Unable to find kme_id of slave sae_id'
      else:
        errmsg = 'Master sae_id for connection not found'
    except:
      errmsg = 'Unknown error'
    #
    if status == 200:
      bits = 256
      nkey = 1
      xtra = list()
      if params:
        bits = params.get(self.key_size_kw, bits)
        nkey = params.get(self.num_keys_kw, nkey)
        xtra = params.get(self.xtra_sae_kw, xtra)
      #
      xtra.append(sae_id)
      #
      # disallow same dest as src?
      for dest in xtra:
        if msae_id == dest:
          status = 400
          errmsg = 'slave sae_id same as master sae_id'
      # cannot have repeated dest ids?
      aset = set(xtra)
      if len(aset) < len(xtra):
        status = 400
        errmsg = 'repeated slave sae_ids'
      # verify dest sae_ids
      for dest in xtra:
        tgt_kme_id = self.qkdnet.saetokme(dest)
        if not tgt_kme_id:
          status = 400
          errmsg = 'slave sae_id not registered: ' + dest
          break
      #
      if status == 200:
        keys = self.createKeys(msae_id, xtra, tgt_kme_id, bits, nkey)
        rparams[self.keys_kw] = keys
    return self.genResp(status, errmsg, rparams)
    
    
  def getkeywid(self, sae_id, params, conn):
    logg.info('getkeywid')
    status = 503
    errmsg = ''
    rparams = dict()
    try:
      msae_id = sae_id
      self.sae_mutex.acquire()
      sae_id = self.conn2sae.get(conn, None)
      self.sae_mutex.release()
      if sae_id:
        src_kme_id = self.qkdnet.saetokme(msae_id)
        if src_kme_id:
          status = 200
          errmsg = 'OK'
        else:
          errmsg = 'Unable to find kme_id of master sae_id'
      else:
        errmsg = 'Slave sae_id for connection not found'
    except:
      errmsg = 'Unknown error'
    #
    if status == 200:
      kids = list()
      if params:
        kid = params.get(self.key_id_kw, None)
        if kid:
          kids.append(kid)
        else:
          klist = params.get(self.key_ids_kw, None)
          if klist:
            for kdict in klist:
              kid = kdict.get(self.key_id_kw, None)
              if kid:
                kids.append(kid)
              else:
                status = 400
                errmsg = 'Missing key_ID in key_IDs list'
                break
      if status == 200 and not kids:
        status = 400
        errmsg = 'No key_ID specified'
      #
      if status == 200:
        keys = self.getKeys(msae_id, sae_id, src_kme_id, self.server_id, kids)
        rparams[self.keys_kw] = keys
        if len(keys) == 0:
          status = 400
          errmsg = 'One or more keys not found'
    return self.genResp(status, errmsg, rparams)
    
    
  def genResp(self, status, errmsg, params):
    retval = str(status) + ' ' + errmsg + '\r\n'
    if params:
      retval += '\r\n' + json.dumps(params) + '\r\n'
    return retval



  def createKeys(self, msae_id, xtra, tgt_kme_id, bits, nkey):
    keys = self.qkdnet.createKeys(msae_id, xtra, self.server_id, tgt_kme_id, bits, nkey)
    # reformat keys w keywords
    rkeys = list()
    for (kid, key) in keys:
      keyd = dict()
      keyd[self.key_id_kw] = kid
      keyd[self.key_kw]    = key
      rkeys.append(keyd)
    return rkeys

    
  def getKeys(self, msae_id, sae_id, src_kme_id, tgt_kme_id, kids):
    keys = self.qkdnet.getKeys(msae_id, sae_id, src_kme_id, tgt_kme_id, kids)
    # reformat keys w keywords
    rkeys = list()
    for (kid, key) in keys:
      keyd = dict()
      keyd[self.key_id_kw] = kid
      keyd[self.key_kw]    = key
      rkeys.append(keyd)
    return rkeys
    

  def disconnect(self, conn):
    self.sae_mutex.acquire()
    sae_id = self.conn2sae.get(conn, None)
    if sae_id:
      self.conn2sae.pop(conn)
      self.qkdnet.unregSAE(self.server_id, sae_id)
      logg.warning('unregistered SAE ID ' + sae_id + ' from connection')
    self.sae_mutex.release()
    #
    super().disconnect(conn)
