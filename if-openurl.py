#!/usr/bin/python
#
# LICENSE: See LICENSE file.
#
# WARNING: The Windows/Linux iface by is EXPERIMENTAL and has nothing to do
#          with good coding, security, etc. USE AT YOUR OWN RISK.
#
import ifaceclientlib, sys
ifaceclientlib.LOG_LEVEL = ifaceclientlib.LOG_WARNING

# Check args.
if len(sys.argv) != 2:
  print "usage: if-openurl.py <url>"
  sys.exit(1)

# Invoke.
url = sys.argv[1]
print ifaceclientlib.Invoke("iface-openurl", url)

