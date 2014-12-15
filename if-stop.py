#!/usr/bin/python
#
# LICENSE: See LICENSE file.
#
# WARNING: The Windows/Linux iface by is EXPERIMENTAL and has nothing to do
#          with good coding, security, etc. USE AT YOUR OWN RISK.
#
import ifaceclientlib
print "Stopping WinLin iface: %s" % (
    str(ifaceclientlib.Invoke("__shutdown"))
  )

