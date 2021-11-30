import random
import logging as logg
from threading import Lock
import base64



def genb(nbits):
  nbytes = (nbits+7)//8
  x = genB(nbytes)
  ns = nbytes*8 - nbits
  if ns:
    x = (x >> ns)
  return x

def genB(nbytes):
  x = 0
  for i in range(nbytes):
    y = random.randrange(256)
    x = (x << 8) | y
  return x

# 4B-2B-2B-2B-6B
def touuid(val):
  uuid = ''
  sh = val & 0xFFFFFFFF
  uuid += hex(sh)[2:].zfill(8) + '-'
  val = (val >> 32)
  for i in range(3):
    sh = val & 0xFFFF
    uuid += hex(sh)[2:].zfill(4) + '-'
    val = (val >> 16)
  sh = val & 0xFFFFFFFFFFFF
  uuid += hex(sh)[2:].zfill(12)
  return uuid

def tob64(val, nbits):
  nbytes = (nbits+7)//8
  x = bytearray()
  for i in range(nbytes):
    x.append(val & 0xFF)
    val = (val >> 8)
  b64 = base64.b64encode(x).decode()
  return b64



class qkdnet:
  def __init__(self):
    logg.getLogger().setLevel(logg.INFO)
    self.qkd_mutex = Lock()
    self.kmes = set()
    self.saes = set()
    self.kme2sae = dict()   # kme to set
    self.sae2kme = dict()   # sae to kme
    self.sae2keys = dict()  # sae to dict[kid]

  def createNodes(self, nkme=3):
    self.qkd_mutex.acquire()
    self.kmes = set()
    self.saes = set()
    self.kme2sae = dict()   # kme to set
    self.sae2kme = dict()   # sae to kme
    self.sae2keys = dict()  # sae to dict
    for i in range(nkme):
      kme_id = touuid(genB(16))
      self.kmes.add(kme_id)
      self.kme2sae[kme_id] = set()
    self.qkd_mutex.release()
    return self.kmes

  def regSAE(self, kme_id, sae_id):
    logg.warning('reg ' + sae_id + ' to ' + kme_id)
    self.qkd_mutex.acquire()
    self.kme2sae[kme_id].add(sae_id)
    self.sae2kme[sae_id] = kme_id
    self.sae2keys[sae_id] = dict()
    self.qkd_mutex.release()
    
  def unregSAE(self, kme_id, sae_id):
    logg.warning('unreg ' + sae_id + ' fr ' + kme_id)
    self.qkd_mutex.acquire()
    self.sae2keys.pop(sae_id)
    self.sae2kme.pop(sae_id)
    self.kme2sae[kme_id].remove(sae_id)
    self.qkd_mutex.release()
    
  def saetokme(self, sae_id):
    self.qkd_mutex.acquire()
    kme_id = self.sae2kme.get(sae_id, None)
    self.qkd_mutex.release()
    return kme_id
    
    
  def createKeys(self, msae_id, sae_ids, src_kme_id, tgt_kme_id, bits, nkey):
    # create keys
    keys = list()
    logg.warning('create keys fr ' + msae_id + ' to ' + str(sae_ids))
    for i in range(nkey):
      keyid  = touuid(genB(16))
      keyval = tob64(genb(bits), bits)
      key = (keyid, keyval)
      keys.append(key)
      logg.info('create key ' + keyid + ': ' + keyval)
    # register keys
    self.qkd_mutex.acquire()
    for sae_id in sae_ids:
      kdict = self.sae2keys[sae_id]
      for (keyid, keyval) in keys:
        kdict[keyid] = keyval
    self.qkd_mutex.release()
    # return keys
    return keys


  def getKeys(self, msae_id, sae_id, src_kme_id, tgt_kme_id, kids):
    keys = list()
    self.qkd_mutex.acquire()
    logg.warning('get keys fr ' + msae_id + ' to ' + str(sae_id))
    kdict = self.sae2keys[sae_id]
    err = False
    for kid in kids:
      kval = kdict.pop(kid, '')
      key = (kid, kval)
      keys.append(key)
      if not kval:
        err = True
        logg.error('missing key ' + kid)
        # restore keys to qkd
        for (kid2, key2) in keys:
          kdict[kid2] = key2
        break
    if err:
      keys = list()
    self.qkd_mutex.release()
    return keys
