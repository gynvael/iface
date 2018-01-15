#!/usr/bin/python
#
# LICENSE: See LICENSE file.
#
# WARNING: The Windows/Linux iface by is EXPERIMENTAL and has nothing to do
#          with good coding, security, etc. USE AT YOUR OWN RISK.
#
# Python Windows/Linux interface library for client apps.
# Handles networking, etc.

import os
import pickle
import select
import socket
import StringIO
import struct
import sys
import threading
from ifaceconfiglib import cfg 

# Constants for debug level in CONFIGURATION section.
LOG_ERROR   =  0
LOG_WARNING =  1
LOG_INFO    =  3
LOG_VERBOSE =  5
LOG_DEBUG   = 10

# -------------------------------------------------------------------
# CONFIGURATION (set values from config file)
# -------------------------------------------------------------------

SECRET = cfg.get('main', 'secret')
BIND_PORT = cfg.getInt('main', 'bind_port')
 
LOG_LEVEL = LOG_DEBUG

# -------------------------------------------------------------------
# End of constants / configs.
# -------------------------------------------------------------------

if len(SECRET) == 0:
  print "This is your time running Windows/Linux iface. You first need to set "
  print "some things up before you can use it."
  print "Please open iface.cfg and set needed values."
  sys.exit(1)

# -------------------------------------------------------------------
# Log function.
def Log(level, msg):

  if level > LOG_LEVEL:
    return # Do nothing.

  # TODO add proper logging
  print "%s: %s" % (
      { LOG_ERROR   : "error",
        LOG_WARNING : "warning",
        LOG_INFO    : "info",
        LOG_VERBOSE : "verbose",
        LOG_DEBUG   : "debug" }[level],
      msg
      )    

# -------------------------------------------------------------------
# Safe pickle (via http://nadiana.com/python-pickle-insecure)
class SafeUnpickler(pickle.Unpickler):
  PICKLE_SAFE = {
      'copy_reg': set(['_reconstructor']),
      '__builtin__': set(['object'])
  }

  def find_class(self, module, name):
    if not module in self.PICKLE_SAFE:
      raise pickle.UnpicklingError(
        'Attempting to unpickle unsafe module %s' % module
        )
      __import__(module)
      mod = sys.modules[module]
      if not name in self.PICKLE_SAFE[module]:
        raise pickle.UnpicklingError(
          'Attempting to unpickle unsafe class %s' % name
        )
      klass = getattr(mod, name)
      return klass
 
  @classmethod
  def loads(cls, pickle_string):
    return cls(StringIO.StringIO(pickle_string)).load()

# -------------------------------------------------------------------
# Net helpers.
def NetHelperSend(sock, data):
  # Format outgoing data.
  data = pickle.dumps(data)
  packet = struct.pack("I", len(data)) + data

  # Send all.
  ret = None
  try:
    ret = sock.sendall(packet)
  except:
    Log(LOG_WARNING, "failed sending data to socket %s" % str(sock))
    return False

  if ret != None:
    Log(LOG_WARNING, "failed sending data to socket %s" % str(sock))
    return False    

  Log(LOG_DEBUG, "sent packet of %u size to %s" % (
    len(packet), str(sock)))

  # Done.
  return True

def NetHelperRecvNBytes(sock, length):
  totalrecv = 0
  data = ""
  while totalrecv < length:
    remaining = length - totalrecv
    if remaining > 0x4000:
      remaining = 0x4000

    success = False
    now_recv = ""
    try:
      now_recv = sock.recv(remaining)
      success = True
    except:
      pass
      
    if now_recv == 0 or not success:
      Log(LOG_WARNING, 
        "got disconnected while receiving data from socket %s" % (
           str(sock)))
      return False

    data += now_recv
    totalrecv = len(data)

  return data

def NetHelperRecv(sock):
  # Receive 4 bytes.
  size_data = NetHelperRecvNBytes(sock, 4)
  if size_data == False:
    Log(LOG_ERROR, "couldn't receive 4 bytes")
    return False

  size = struct.unpack("I", size_data)[0]

  # Receive packet.
  data = NetHelperRecvNBytes(sock, size)
  if data == False:
    Log(LOG_ERROR, "couldn't receive data with size:" + str(size))
    return False

  Log(LOG_DEBUG, "recv packet of %u len from %s" % (
    size, str(sock)))

  # Unpickle.
  try:
    data = SafeUnpickler.loads(data)
  except:
    Log(LOG_ERROR, "could not unpickle packet from %s" % str(sock))
    return False

  # Done.
  Log(LOG_DEBUG, "data == '%s'" % str(data))
  return data

# -------------------------------------------------------------------
# Invoke a command.
def Invoke(cmd, *args):
  
  # Create the packet.
  data = {
      "command" : cmd,
      "args"    : args
      }

  # Connect to host.
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    s.connect(("127.0.0.1", BIND_PORT))

    # Poor man's auth.
    s.sendall(SECRET)

  except:
    Log(LOG_ERROR, "could not connect to local iface")
    raise

  # Send data.
  res = NetHelperSend(s, data)
  if res == False:
    raise Exception('error send')

  # Receive result.
  res = NetHelperRecv(s)
  if res == False:
    raise Exception('error recv')

  # Done.
  return res


  







