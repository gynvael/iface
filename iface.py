#!/usr/bin/python
#
# LICENSE: See LICENSE file.
#
# WARNING: The Windows/Linux iface by is EXPERIMENTAL and has nothing to do
#          with good coding, security, etc. USE AT YOUR OWN RISK.
#
# INITIAL SETUP: please scroll down looking for "CONFIGURATION" section.
#
# This app must be run both on -windows and linux.
# Please use either --windows or --linux parameters to specify
# where is it executed.

# *** Architecture
# 
#            +-------+                   +-------+
#            : HOST  : <--tcp-ctrl-chan- :  VM   +
#            : iface :                   : iface +
#            +-------+                   +-------+
#             ^     ^                     ^     ^
#             :     :                     :     :
#             t     t                     t     t
#             c     c                     c     c
#             p     p                     p     p
#             :     :                     :     :
#            cmd1  cmd2                  cmd1  cmd2
#
# The iface is always running. It's job is to be aware if
# the second iface is online, and to transmit commands to it.
# It should also provide some simple data transmision mechanism
# and/or data storage mechanisms (to e.g. store settings and
# stats).
# The IFACE_VM can assume that the IFACE_HOST is always online.
# The IFACE_HOST should check with the VM manager to see if the 
# IFACE_VM machine is online before attempting to send a command.
# Also, if possible, it should try to UDP-ping the IFACE_VM to
# be sure no timeout will occure.
#
# Additionally the IFACE_HOST should be aware of path mapping
# between both machines, and it should provide a way to translate
# a path VM->HOST and HOST->VM. It should be aware of both the
# shared folders via VM mechanisms and SSHFS mounts (though
# they can be placed in a config file or sth).
#
# *** By example
# The l-cmd command executes a linux terminal in the given
# work directory (it also takes care of translating the directory).
# It works the following way:
# 1. User executes l-cmd, which is actually l-cmd.py script.
# 2. The script imports the WinLin Iface library.
# 3. It invokes "l-cmd" with CWD as parameter (by creating a
#    tcp connection to the IFACE).
# 4. The IFACE receives the command/parameter and invokes
#    the proper command handler.
# 5. The command handler invokes the "path-translate" command
#    with CWD as the parameter.
# 6. Since it's a IFACE_HOST command, the translation is done
#    in place, and the new path is returned.
# 7. Next, the l-cmd command is sent to IFACE_VM with the
#    translated path as CWD.
# 8. On IFACE_VM the l-cmd handler is invoked.
# 9. The handler launches gnome-terminal in the given directory.
# 10. A result is returned all the way.

# Constants for debug level in CONFIGURATION section.
LOG_ERROR   =  0
LOG_WARNING =  1
LOG_INFO    =  3
LOG_VERBOSE =  5
LOG_DEBUG   = 10

import os
import pickle
import select
import socket
import StringIO
import struct
import subprocess
import sys
import time
import threading
if sys.platform != 'win32':
  import fcntl
from ifaceconfiglib import cfg

# -------------------------------------------------------------------
# CONFIGURATION (set values from config file)
# -------------------------------------------------------------------

SECRET = cfg.get('main', 'secret')
HOME_PATH_ON_VM = cfg.get('main', 'home_path')
BIND_PORT = cfg.getInt('main', 'bind_port')
TERMINAL_CMD = cfg.get('main', 'terminal_cmd')
REMOTE_IP_LIST = eval(cfg.get('main', 'remote_ip_list'))

CMDS={
    "iface-info"    : "CMD_iface_info", # Returns some info.
    "iface-ping"    : "CMD_ping",       # Returns "pong"
    "iface-openurl" : "CMD_openurl",    # Opens http or https url.
    "iface-l-cmd"   : "CMD_l_cmd",      # Spawns a linux console.
    "translate-path": "CMD_translate_path", # Translates path.
    }

LOG_LEVEL = LOG_DEBUG
# -------------------------------------------------------------------
# End of constants / configs.
# -------------------------------------------------------------------

print "Windows/Linux iface by gynvael.coldwind//vx"

def Usage():
  print "usage: iface --windows|--linux"
  print ""
  print "Run with --windows on Host/Windows or with --linux on VM/Linux."

if len(SECRET) == 0:
  print "This is your time running Windows/Linux iface. You first need to set "
  print "some things up before you can use it."
  print "Please open iface.cfg and set needed values."
  sys.exit(1)

if len(sys.argv) != 2:
  Usage()
  sys.exit(1)

if sys.argv[1] not in ['--windows', '--linux']:
  Usage()
  sys.exit(2)

IFACE_HOST="HOST"
IFACE_VM="VM"
IFACE={"--windows":IFACE_HOST, "--linux":IFACE_VM}[sys.argv[1]]

IFACE_REMOTE="REMOTE"
IFACE_LOCAL="LOCAL"

BIND_IP={
    IFACE_HOST: REMOTE_IP_LIST[0],
    IFACE_VM  : REMOTE_IP_LIST[1]
    }[IFACE]

CTRL_CHANNEL_ONLINE = False
CTRL_CHANNEL_SOCKET = None
CTRL_CHANNEL_THREAD = None
EVENT_CLOSE_CTRL_CHANNEL = threading.Event()

# Host? Then we need another import
if IFACE == IFACE_HOST:
  import ctypes


# -------------------------------------------------------------------
# Locked list.
class LockedList():

  def __init__(self):
    self.lock = threading.Lock()
    self.d    = []

  def snapshot(self):
    self.lock.acquire()
    d_copy = self.d[:]
    self.lock.release()
    return d_copy

  def append(self, element):
    self.lock.acquire()
    self.d.append(element)
    self.lock.release()

  def insert(self, element):
    self.lock.acquire()
    self.d.insert(0, element)
    self.lock.release()

  def pop(self):
    self.lock.acquire()
    res = None
    if len(self.d) > 0:
      res = self.d.pop()
    self.lock.release()
    return res

  def remove(self, element):
    res = False
    self.lock.acquire()
    if element in self.d:
      self.d.remove(element)
      res = True
    self.lock.release()
    return res

  def find(self, element):
    self.lock.acquire()
    res = -1
    if element in self.d:
      res = self.d.index(element)
    self.lock.release()
    return res

  def raw_lock(self):
    self.lock.acquire()
    return self.d

  def raw_release(self):
    self.lock.release()

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
# Some run-time globals.
ACTIVE_HANDLERS = LockedList()
CTRL_SEND_LIST  = LockedList()
EVENT_SEND_LIST_POPULATED = threading.Event()

REPLY_REGISTRY = {}
REPLY_REGISTRY_LOCK = threading.Lock()

CID_COUNTER = 0
CID_COUNTER_LOCK = threading.Lock()

# -------------------------------------------------------------------
# Control packet sender / registry functions.

def CtrlSendReply(cid, result):
  global CTRL_SEND_LIST
  global EVENT_SEND_LIST_POPULATED

  # Create packet.
  packet = {
      "reply_cid": cid,
      "result"   : result
      }

  # Append packet to send list.
  CTRL_SEND_LIST.insert(packet)

  # Mark list as populated.
  EVENT_SEND_LIST_POPULATED.set()

  # Done.
  return

def CtrlSendRequest(cid, cmd, args):
  global CTRL_SEND_LIST
  global EVENT_SEND_LIST_POPULATED

  # Create packet.
  packet = {
      "cid"     : cid,
      "command" : cmd,
      "args"    : args
      }

  # Append packet to send list.
  CTRL_SEND_LIST.insert(packet)

  # Mark list as populated.
  EVENT_SEND_LIST_POPULATED.set()

  # Done.
  return

def CtrlRecvReply(cid, result):
  global REPLY_REGISTRY_LOCK
  global REPLY_REGISTRY  

  # Lock the registry.
  REPLY_REGISTRY_LOCK.acquire()

  # Is anyone waiting for this reply?
  if cid not in REPLY_REGISTRY:
    # Log it.
    Log(LOG_WARNING,
      "received ctrl reply (cid=%s), but no one is waiting for it" % (
        str(cid)
        ))
    REPLY_REGISTRY_LOCK.release()
    return

  # Pop it so we can clear the lock.
  info = REPLY_REGISTRY.pop(cid)
  REPLY_REGISTRY_LOCK.release()

  # Set the data and ping the waiting thread.
  info["data"].append(result) # Return by adding to refered list.
  info["event"].set() # This should wake up the thread.

  # That's that.
  return

def CtrlRegisterCID(cid):
  global REPLY_REGISTRY_LOCK
  global REPLY_REGISTRY

  # Create info struct.
  info = {
      "data" : [], # Result will be added here.
      "event" : threading.Event()
      }

  # Register.
  REPLY_REGISTRY_LOCK.acquire()
  REPLY_REGISTRY[cid] = info
  REPLY_REGISTRY_LOCK.release()

  # Done.
  return info

def CtrlGetCID():
  global CID_COUNTER
  global CID_COUNTER_LOCK
  CID_COUNTER_LOCK.acquire()
  ret = CID_COUNTER
  CID_COUNTER += 1
  CID_COUNTER_LOCK.release()
  return ret


# -------------------------------------------------------------------
# Run handler
def RunHandlerByPacket(packet, info):
  global EVENT_END
  global CMDS
  
  cmd = packet["command"]
  arg = packet["args"]

  # Is this a special command?
  if cmd == "__shutdown":
    Log(LOG_INFO, "__shutdown command received")
    EVENT_END.set()
    return True

  # Is this a known command?
  if cmd not in CMDS:
    Log(LOG_WARNING, "unknown command \"%s\"" % cmd)
    raise Exception('unknown command')

  # Find the handler.
  handler_name = CMDS[cmd]
  if handler_name not in globals():
    Log(LOG_ERROR,
      "handler \"%s\" not found for known command \"%s\"" % (
        handler_name, cmd))
    raise Exception('handler not found command')
        
  handler = globals()[handler_name]

  arg = tuple([info] + list(arg))

  # Execute handler.        
  result = handler(*arg)
  return result

# Run handler
def RunHandlerByCtrlPacket(packet):

  # This can be either a reply packet, or a new command.
  # Let's check.

  if "reply_cid" in packet:
    # A reply packet.
    RunHandlerByCtrlReplyPacket(packet)

  elif "command" in packet:
    # A command packet.
    RunHandlerByCtrlCommandPacket(packet)

  else:
    # Should never be reached.
    Log(LOG_ERROR, "weird ctrl packet, ignoring")

  # Done.
  return

# Handle reply packet.
def RunHandlerByCtrlReplyPacket(packet):

  cid    = packet["reply_cid"]
  result = packet["result"]

  Log(LOG_VERBOSE, "received reply to request (cid=%s)" % (
    str(cid)
    ))

  # Commit results.
  CtrlRecvReply(cid, result)

  # Done.
  return


# Handle command packet.
def RunHandlerByCtrlCommandPacket(packet):
  global CMDS
  global EVENT_END

  cmd = packet["command"]
  arg = packet["args"]
  cid = packet["cid"]

  # Log.
  Log(LOG_VERBOSE, "remote request (cid=%s) for cmd \"%s\"" % (
    str(cid), cmd
    ))

  # Is this a special command?
  if cmd == "__shutdown":
    Log(LOG_INFO, "__shutdown command received from remote")
    EVENT_END.set()
    CtrlSendReply(cid, True)
    return

  # Is this a known command?
  if cmd not in CMDS:
    Log(LOG_WARNING, "unknown command \"%s\"" % cmd)
    return

  # Find the handler.
  handler_name = CMDS[cmd]
  if handler_name not in globals():
    Log(LOG_ERROR,
      "handler \"%s\" not found for known command \"%s\"" % (
        handler_name, cmd))
    return
        
  handler = globals()[handler_name]

  info = {
      "source" : IFACE_REMOTE
      }

  arg = tuple([info] + list(arg))

  # Execute handler.
  result = handler(*arg)

  # Send reply.
  Log(LOG_VERBOSE, "sending reply to request (cid=%s)" % (
    str(cid)
    ))

  CtrlSendReply(cid, result)

  # Done.
  return

# -------------------------------------------------------------------
# CtrlPacket handler thread.
class CtrlPacketHandler(threading.Thread):

  def __init__(self, packet):
    global ACTIVE_HANDLERS
    threading.Thread.__init__(self)

    # Copy properties.
    self.packet = packet

    # Add self to handler list.
    ACTIVE_HANDLERS.append(self)

    # Start.
    self.start()

  def run(self):
    global ACTIVE_HANDLERS

    Log(LOG_DEBUG, "starting new ctrl packet handler thread %s" % (
      str(self)))
    RunHandlerByCtrlPacket(self.packet)

    ACTIVE_HANDLERS.remove(self)

    Log(LOG_DEBUG, "ending ctrl packet handler thread %s" % (
      str(self)))    
    return 0

# -------------------------------------------------------------------
# Connection handler thread.
class ThreadHandler(threading.Thread):

  def __init__(self, sock, address, conn_type):
    global ACTIVE_HANDLERS
    threading.Thread.__init__(self)

    # Copy properties.
    self.sock      = sock
    self.address   = address
    self.conn_type = conn_type

    # Add self to the list.
    ACTIVE_HANDLERS.append(self)   

    # Start.
    self.start()

  def run(self):
    global ACTIVE_HANDLERS

    # Get the packet.
    packet = NetHelperRecv(self.sock)

    if packet != False:
      res = None
      try:
        # Gather info.
        info = {
            "source"  : self.conn_type
            }

        res = RunHandlerByPacket(packet, info)
      except:
        # TODO: Log this
        print "Unexpected error:", sys.exc_info()
      else:
        NetHelperSend(self.sock, res)

    # Finalize.
    self.sock.close()
    self.sock = None

    # Remove self and return.
    ACTIVE_HANDLERS.remove(self)    
    return 0

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
    return False

  size = struct.unpack("I", size_data)[0]

  # Receive packet.
  data = NetHelperRecvNBytes(sock, size)
  if data == False:
    return False

  Log(LOG_DEBUG, "recv packet of %u len from %s" % (
    size + 4, str(sock)))

  # Unpickle.
  try:
    data = SafeUnpickler.loads(data)
  except:
    Log(LOG_ERROR, "could not unpickle packet from %s" % str(sock))
    return False

  # Done.
  return data

def NetHelperGetRawPacket(data):

  # Packet with data is atleast 4 bytes size.
  if len(data) < 4:
    return None

  # Extract size.
  size = struct.unpack("I", data[:4])[0]

  Log(LOG_DEBUG, "raw packet size check: declared=%u, is=%u" % (
    size, len(data) - 4
    ))

  # Add the already received size bytes.
  size += 4

  # Is there enough data?
  if len(data) < size:
    return None

  # Get the data and return it.
  return data[:size]

def NetHelperRecvFromString(packet):
  # This function assumes it's a correct packet.
  size = struct.unpack("I", packet[:4])[0]
  data = packet[4:]

  if len(data) != size:
    Log(LOG_ERROR, "sane packet was insane (%u vs %u)" % (
      len(data), size
      ))

  Log(LOG_DEBUG, "recv packet of %u len from buffer" % (
    size + 4))

  # Unpickle.
  try:
    data = SafeUnpickler.loads(data)
  except:
    Log(LOG_ERROR, "could not unpickle packet from buffer: %s" %(
      sys.ecx_info()
      ))
    raise

  # Done.
  return data

# -------------------------------------------------------------------
class ThreadCtrlChannelSender(threading.Thread):

  def __init__(self, sock):
    threading.Thread.__init__(self)

    # Copy.
    self.sock = sock

    # Start.
    self.start()

  def run(self):
    global EVENT_CLOSE_CTRL_CHANNEL
    global EVENT_SEND_LIST_POPULATED
    global CTRL_SEND_LIST
    Log(LOG_DEBUG, "ctrl sender thread started %s" % str(self))

    # Until it's time to die.
    while not EVENT_CLOSE_CTRL_CHANNEL.is_set():

      # Clear the population event.
      EVENT_SEND_LIST_POPULATED.clear()

      # Clear the list.
      while True:

        # Try to get something from the list.
        data = CTRL_SEND_LIST.pop()
        if data == None:
          break

        # Send it.
        NetHelperSend(self.sock, data)

      # Wait until the list is populated again.
      EVENT_SEND_LIST_POPULATED.wait(1.0)

      continue

    # Guess it's time to finish.
    Log(LOG_DEBUG, "ctrl sender thread finished %s" % str(self))
    return 0

# -------------------------------------------------------------------
class ThreadGuardCtrl(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.start()

  def run(self):
    global REMOTE_IP_LIST
    global BIND_PORT
    global EVENT_END

    while not EVENT_END.is_set():

      # Try to connect.
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      if IFACE == IFACE_VM:
        flags = fcntl.fcntl(s.fileno(), fcntl.F_GETFD)
        fcntl.fcntl(s.fileno(), fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

      try:
        s.connect((REMOTE_IP_LIST[0], BIND_PORT))

        # Poor man's auth.
        s.sendall(SECRET)

      except:
        Log(LOG_DEBUG, "could not connect to host iface")

        # Sleep before retry.
        time.sleep(5.0)

        # Retry.
        continue

      # Launch handler.
      t = ThreadCtrlChannelServer(s, ("n/a", 0))
      t.join()
      
      # Got disconnected. Clean up.
      s.close()
      s = None
      continue

    # Done
    return

# -------------------------------------------------------------------
class ThreadCtrlChannelServer(threading.Thread):

  def __init__(self, sock, address):
    global CTRL_CHANNEL_THREAD
    threading.Thread.__init__(self)

    # Copy.
    self.sock = sock
    self.address = address
    self.sender_thread = None

    # Replace thread marker.
    self.old_thread = CTRL_CHANNEL_THREAD
    CTRL_CHANNEL_THREAD = self

    # Start.
    self.start()

  def run(self):
    global CTRL_CHANNEL_THREAD
    global CTRL_CHANNEL_SOCKET
    global CTRL_CHANNEL_ONLINE
    global EVENT_CLOSE_CTRL_CHANNEL
    global EVENT_END
    Log(LOG_DEBUG, "ctrl server thread started %s" % str(self))

    # Is there already a channel? If so, replace it.
    if self.old_thread:

      # Graceful shutdown the old thread.
      EVENT_CLOSE_CTRL_CHANNEL.set()

      # Wait for old thread to end
      self.old_thread.join()

    # Make sure this is cleared in either case.
    EVENT_CLOSE_CTRL_CHANNEL.clear()

    # If we need to end, it's a good time to do it now.
    # XXX: Not sure about this workaround, but it should be kinda OK.
    if EVENT_END.is_set():
      Log(LOG_DEBUG, "ctrl server thread ended gracefully (in) %s" % (
        str(self)
        ))      
      return 0

    # Start initializing everything.
    CTRL_CHANNEL_SOCKET = self.sock
    CTRL_CHANNEL_THREAD = self
    self.sender_thread = ThreadCtrlChannelSender(self.sock)

    # Mark as ONLINE.
    CTRL_CHANNEL_ONLINE = True

    # Main recv loop.
    data = ""

    while not EVENT_CLOSE_CTRL_CHANNEL.is_set():

      # Select.
      rr,rw,err = select.select([self.sock], [], [], 1.0)

      # Was this a timeout?
      if len(rr) == 0 and len(rw) == 0 and len(err) == 0:
        continue

      # Read.
      try:
        recv_data = self.sock.recv(0x4000)
      except:
        Log(LOG_INFO, "control channel died: %s" % (
          str(sys.exc_info())))
        break

      # Closed?
      if len(recv_data) == 0:
        Log(LOG_INFO, "control channel died")
        break

      # Add to data.
      Log(LOG_DEBUG, "ctrl channel got another %u bytes" % (
          len(recv_data)
          ))
      data += recv_data

      # There can be more than one packet ready.
      fatal_error = False      
      while True:
  
        # Is the full packet ready?
        raw_packet = NetHelperGetRawPacket(data)
        if raw_packet == None:
          Log(LOG_DEBUG, "no more raw packets ready")
          break # Not yet.

        # Fix data buffer.
        data = data[len(raw_packet):]
              
        # Extract packet.
        try:
          packet = NetHelperRecvFromString(raw_packet)
        except:
          Log(LOG_INFO,
              "control channel got invalid data, dying: %s" % (
                str(sys.exc_info())
                ))
          fatal_error = True
          break

        # Well, this packet needs to be specially handled.
        t = CtrlPacketHandler(packet)

        # And that's it I guess.
        continue

      # Anything bad happend?
      if fatal_error:
        break

      # Conitnue.
      continue      

    # Seems we need to exit.
    CTRL_CHANNEL_ONLINE = False    
    self.sock.close()

    # Make sure event is set.
    if not EVENT_CLOSE_CTRL_CHANNEL.is_set():
      EVENT_CLOSE_CTRL_CHANNEL.set()

    # Wait for sender thread.
    self.sender_thread.join()

    # Finalize
    CTRL_CHANNEL_SOCKET = None
    Log(LOG_DEBUG, "ctrl server thread ended gracefully %s" % (
      str(self)
      ))
    return 0

# -------------------------------------------------------------------
# Main listening thread.
class ThreadMainNet(threading.Thread):

  def __init__(self):
    threading.Thread.__init__(self)

    # Just run self.
    self.start()

  def run(self):
    global CMDS
    global IFACE
    global BIND_PORT
    global EVENT_END
    global CTRL_CHANNEL_ONLINE
    global CTRL_CHANNEL_SOCKET

    Log(LOG_DEBUG, "main thread started")

    try:
      # Create local listening socket.
      socket_local = CreateListeningSocket("127.0.0.1", BIND_PORT)
  
      # Create remote listening socket if needed.
      socket_remote = False
      if IFACE==IFACE_HOST:
        socket_remote = CreateListeningSocket(BIND_IP, BIND_PORT)

      # Connect to HOST if required.

    except socket.error, msg:
      Log(LOG_ERROR, msg)
      EVENT_END.set() # Make the app exit.
      return 1

    # Main loop.
    # This loop handles only the incomming connections.
    # All the handlers/reads/writes are handled in separate threads.

    # Is the ctrl channel online?
    socket_ctrl = False
   
    # Create translation dict.
    sock_to_type = {
        socket_local : IFACE_LOCAL,
        }
    if socket_remote:
      sock_to_type[socket_remote] = IFACE_REMOTE

    # Create a select list.
    socket_poll = [ socket_local ]
    if socket_remote:
      socket_poll.append(socket_remote)

    # Loop
    while not EVENT_END.is_set():

      # Any incomming connection?
      rr,rw,err = select.select(socket_poll,[],[], 1.0)

      # Was this a timeout?
      if len(rr) == 0 and len(rw) == 0 and len(err) == 0:
        continue

      # Anything ready to be accepted?
      for sock in rr:
        (new_sock, address) = sock.accept()

        # Is this a local or remote connection?
        conn_type = sock_to_type[sock]

        Log(LOG_VERBOSE, "connection from %s:%u (%s)" % (
          address[0], address[1], conn_type
          ))

        # Is this connection allowed?
        if conn_type == IFACE_REMOTE and address[0] not in REMOTE_IP_LIST:
          
          # Kill the connection. It's not allowed.
          Log(LOG_INFO, 
              "killing disallowed REMOTE connection form %s:%u" %
              address)

          new_sock.close()
          new_sock = None

          # Continue.
          continue

        # Poor man's authentication.
        try:
          # Auth must arrive at most 2 seconds after connection is established.
          timeout = new_sock.gettimeout()
          new_sock.settimeout(2)
          auth = new_sock.recv(len(SECRET))

          # Yes, I know the auth packet might be split into several, But I don't
          # care about it as in normal usecase it will always arrive as one
          # packet.
          
          if auth != SECRET:
            Log(LOG_WARNING, "auth of %s:%u failed" % address)
            new_sock.close()
            new_sock = None
            continue

          Log(LOG_VERBOSE, "auth of %s:%u successful" % address)
        except socket.timeout, msg:
          Log(LOG_INFO, "timed out at auth %s:%u" % address)
          new_sock.close()
          new_sock = None
          continue
        except socket.error, msg:
          Log(LOG_INFO, "disconnected at auth %s:%u" % address)
          new_sock.close()
          new_sock = None
          continue


        # At this point it's a good connection that should be maintained.

        # If this is a local connection, just run the handler.
        if conn_type == IFACE_LOCAL:
          t = ThreadHandler(new_sock, address, conn_type)
          Log(LOG_DEBUG,
              "created local-cmd handler thread %s" % str(t))
          continue

        # Otherwise, start the new ctrl channel thread.
        # The new thread will take care of shutting down the old one.
        t = ThreadCtrlChannelServer(new_sock, address)
        Log(LOG_INFO, "new ctrl channel created, thread %s" % str(t))

        # Anything else?
        continue

    # Done. Kill sockets.
    socket_local.close()
    socket_local = None

    if socket_remote:
      socket_remote.close()
      socket_remote = None

    if socket_ctrl:
      socket_ctrl.close()
      socket_ctrl = None

    # Return.
    return 0 # Normal shutdown


# -------------------------------------------------------------------
# Main.
def Main():

  # Create the new end event.
  global EVENT_END
  global CTRL_CHANNEL_THREAD
  global CTRL_CHANNEL_ONLINE
  EVENT_END = threading.Event()

  # Create the main networking threads.
  thread_net = ThreadMainNet()
  thread_ctrl = None
  
  if IFACE == IFACE_VM:
    thread_ctrl = ThreadGuardCtrl()

  # Wait until end.
  EVENT_END.wait()

  # -----------------------------------------------------------------
  # Clean everything.

  # Inform second IFACE of shutdown.
  # TODO

  # Wait for all handlers to finish.
  # TODO

  # Inform ctrl channel thread to shutdown.
  if CTRL_CHANNEL_ONLINE:
    EVENT_CLOSE_CTRL_CHANNEL.set()

  # The networking thread should get the same signal,
  # but it's slow to react. Wait for it to finish.
  thread_net.join()

  # Wait for the ctrl channel thread to finish as well.
  if thread_ctrl:
    thread_ctrl.join()

  if CTRL_CHANNEL_ONLINE:
    finished = False
    while not finished:
      try:
        CTRL_CHANNEL_THREAD.wait()
        finished = True
      except:
        # Thread is still initializing.
        time.sleep(0.250)
        continue

  # That's it.
  print "info: Clean exit."
  return 0

# -------------------------------------------------------------------
# Create a listening socket.
def CreateListeningSocket(bind_ip, bind_port):

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if IFACE == IFACE_VM:
    flags = fcntl.fcntl(s.fileno(), fcntl.F_GETFD)
    fcntl.fcntl(s.fileno(), fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

  s.bind((bind_ip, bind_port))
  s.listen(5)

  return s

# -------------------------------------------------------------------
# Log function.
def Log(level, msg):
  global __LOG_LOCK

  if level > LOG_LEVEL:
    return # Do nothing.

  # Is lock created?
  if "__LOG_LOCK" not in globals():
    __LOG_LOCK = threading.Lock()

  # Lock.
  __LOG_LOCK.acquire()

  # TODO add proper logging
  print "%s: %s" % (
      { LOG_ERROR   : "error",
        LOG_WARNING : "warning",
        LOG_INFO    : "info",
        LOG_VERBOSE : "verbose",
        LOG_DEBUG   : "debug" }[level],
      msg
      )    

  # Unlock.
  __LOG_LOCK.release()

# -------------------------------------------------------------------
# Invoke command.
def Invoke(where, cmd, *args):
  global IFACE

  # Need to translate where to relative?
  where = IFACEtoRelative(where)

  # Format data.
  data = {
      "command" : cmd,
      "args"    : args
    }

  # Call proper handler.
  return {
      IFACE_LOCAL : InvokeLocalWorker,
      IFACE_REMOTE : InvokeRemoteWorker
      }[where](data)

# -------------------------------------------------------------------
# Invoke command on remote end.
def InvokeRemoteWorker(data):

  # Get a CID.
  cid = CtrlGetCID()

  # Register waiting for this data.
  info = CtrlRegisterCID(cid)

  # Send the request (this actually just schedules a send and
  # returns).
  CtrlSendRequest(cid, data["command"], data["args"])

  # Wait for data.
  ret = info["event"].wait(10.0)
  if ret == False:
    Log(LOG_ERROR, "remote invoke timed out (cid=%s)" % str(cid))
    return None

  # Your data is ready.
  result = info["data"][0]
  return result

# -------------------------------------------------------------------
# Invoke command locally.
def InvokeLocalWorker(data):
  info = {
      "source"  : IFACE_LOCAL
      }

  return RunHandlerByPacket(data, info)

# -------------------------------------------------------------------
# Get IFACE to desired form.
def IFACEtoAbsolute(i):
  global IFACE
  if i == IFACE_HOST or i == IFACE_VM:
    return i

  if IFACE == IFACE_HOST and i == IFACE_LOCAL:
    return IFACE_HOST

  if IFACE == IFACE_VM and i == IFACE_REMOTE:
    return IFACE_HOST

  return IFACE_VM

def IFACEtoRelative(i):
  global IFACE
  if i == IFACE_LOCAL or i == IFACE_REMOTE:
    return i

  if IFACE == IFACE_HOST and i == IFACE_HOST:
    return IFACE_LOCAL

  if IFACE == IFACE_VM and i == IFACE_VM:
    return IFACE_LOCAL

  return IFACE_REMOTE

# -------------------------------------------------------------------
# COMMAND HANDLERS.
# Each command handler takes at least 1 argument called "info".
# This argument contains information like:
#  info["source"] - source of command, can be either "REMOTE" or
#                   "LOCAL"
#  info["ctrl_status"] - is the ctrl channel alive? True | False

# -------------------------------------------------------------------
# CMD_ping
def CMD_ping(info):
  return "pong"

# -------------------------------------------------------------------
# CMD_iface_info
def CMD_iface_info(info):
  global IFACE
  global CTRL_CHANNEL_ONLINE
  local_info = "-- WinLin Iface Info for %s\n" % IFACE
  local_info += "Contorl Channel State: %s\n" % (
      ["OFFLINE", "ONLINE"][CTRL_CHANNEL_ONLINE]
      )
  local_info += "Source of This Command: %s\n" % (
      info["source"]
      )
  local_info += "Ping command on self: %s\n" % (
      Invoke(IFACE_LOCAL, "iface-ping")
      )
  local_info += "Ping command on remote: %s\n" % (
      Invoke(IFACE_REMOTE, "iface-ping")
      )  

  # That's it if it was remotly invoked.
  if info["source"] == IFACE_REMOTE:
    return local_info

  # Else, invoke the remote (if it's online)
  remote_info = "[remote end is offline; cannot grab info]"
  if CTRL_CHANNEL_ONLINE:
    remote_info = Invoke(IFACE_REMOTE, "iface-info")

  # And return.
  return local_info + "\n" + remote_info

# -------------------------------------------------------------------
# CMD_translate_path
def CMD_translate_path(info, path):
  global IFACE

  # If we are the VM, we don't handle this.
  if IFACE == IFACE_VM:
    return Invoke(IFACE_HOST, "translate-path", path)

  # Guess we are the HOST, so it's our job to handle this.
 
  # If path is empty, just return.
  if len(path) == 0:
    return ""

  # What kind of path his this?
  path_type = "UNKNOWN"
  if path[0] == '/':
    path_type = "LINUX"
  elif path[1] == ':' and path[0].isalpha():
    path_type = "WINDOWS"
  else:
    Log(LOG_WARNING, "translate-path: unknown path type \"%s\"" % (
          path
          ))
    return ""

  # Return converted path.
  return {
      "WINDOWS" : translate_path_to_linux,
      "LINUX"   : translate_path_to_windows
      }[path_type](path)

def translate_path_to_linux(path):

  initial_path = path
  
  # Is this already a linux path?
  # The L: drive on windows is mapped to the linux disk root.
  if path[0].upper() == 'L':

    # The answer is easy in this case.
    path = path[2:].replace('\\', '/')

    # TODO: check if it's not in /media/sf_?_DRIVE/
    
    Log(LOG_INFO, "translate-path: [L] \"%s\" -> \"%s\"" % (
          initial_path, path
          ))
    
    # Done.
    return path

  # Seems it is windows path after all.
  # Is it one of the mapped drives?
  if not path[0].upper() in ['C', 'D', 'E', 'I', 'W', 'B']:

    # Nothing we can do.
    path = HOME_PATH_ON_VM

    # Done.
    Log(LOG_INFO, "translate-path: [!] \"%s\" -> \"%s\"" % (
          initial_path, path
          ))
    return path

  # So it is one of the drives.
  drive_letter = path[0].lower()
  path = "/%s/%s" % (
      drive_letter,
      path[2:].replace('\\', '/')
      )

  # Remove redundant slashes in path.
  while path.find('//') != -1:
    path = path.replace('//', '/')

  # CONFIGURE HERE
  # Example of how to handle a link:
  # If this is /d/link/, switch it to /i/link/.
  #if path.startswith("/d/link/") or path == "/d/link":
  #  path = "/i/link" + path[7:]
  # END OF CONFIGURE

  # Done.
  Log(LOG_INFO, "translate-path: [C] \"%s\" -> \"%s\"" % (
        initial_path, path
        ))

  return path

def translate_path_to_windows(path):

  initial_path = path

  # CONFIGURE HERE  
  # Is this one of the windows drives?
  windows_drives_links  = [ "/c/", "/d/", "/e/", "/i/" ]
  windows_drives_mounts = [
      "/media/sf_C_DRIVE/",
      "/media/sf_D_DRIVE/",
      "/media/sf_E_DRIVE/",
      "/media/sf_I_DRIVE/",
      ]
  # END OF CONFIGURE  

  is_in_links  = filter(path.startswith, windows_drives_links)
  is_in_mounts = filter(path.startswith, windows_drives_mounts)

  if is_in_links or is_in_mounts:

    # Yes, this is a windows drive.
    if is_in_links:
      path = "%s:\%s" % ( path[1], path[3:] )
    else:
      path = "%s:\%s" % ( path[10], path[18:] )

    path = path.replace('/', '\\')

    # Done.
    Log(LOG_INFO, "translate-path: [W] \"%s\" -> \"%s\"" % (
          initial_path, path
          ))
    return path

  # Seems this is a linux path after all.
  path = "L:\\%s" % path.replace('/', '\\')

  # Done.
  Log(LOG_INFO, "translate-path: [c] \"%s\" -> \"%s\"" % (
        initial_path, path
        ))

  return path

# -------------------------------------------------------------------
# CMD_openurl
def CMD_openurl(info, url):
  global IFACE

  # If we are the VM, we don't handle this.
  if IFACE == IFACE_VM:
    return Invoke(IFACE_HOST, "iface-openurl", url)

  # Guess we are the HOST, so it's our job to handle this.
  
  # Check if it's http or https urls.
  if url[:7] != "http://" and url[:8] != "https://":
    Log(LOG_WARNING, "iface-openurl: unsupported url type: \"%s\"" % (
      url
      ))
    return (False, "unsupported url type")

  # Pass to the shell.
  ctypes.windll.shell32.ShellExecuteA(0, 'open', url, None, "", 1)  
  
  # Done.
  return True

# -------------------------------------------------------------------
# CMD_l_cmd
def CMD_l_cmd(info, cwd):
  global IFACE

  # XXX: This is basically a command execution anyways.

  # If we are the HOST, we don't handle this.
  if IFACE == IFACE_HOST:
    return Invoke(IFACE_VM, "iface-l-cmd", cwd)

  # Guess we are the VM, so it's our job to handle this.

  # If this is not a linux cwd, we need to convert it.
  if cwd[0] != '/':
    cwd = Invoke(IFACE_HOST, "translate-path", cwd)

    # Default?
    if not cwd:
      cwd = HOME_PATH_ON_VM

  # Spawn the terminal.
  cwd = cwd.replace("'", "\\'")
  command = "(cd '%s'; %s &)" % (cwd, TERMINAL_CMD)

  # Spawn.
  if subprocess.call(command, shell=True) == 0:
    # subprocess.call by default returns 0 with process success return code.
    # Unfortunately, ifaceclientlib will understand such status as a false and
    # will thrown an exception as a result.
    return "1"
  else:
    return "0"

# -------------------------------------------------------------------
# Everything else is in main.
sys.exit(Main())


