from py80211.scan import *
import netlink.capi as nl
import sys

ifidx = nl.if_nametoindex(sys.argv[1])
level = nl.NL_CB_DEBUG
if sys.argv[2] == 'start':
	rh = sched_scan_start(ifidx, level)
	rh.add_matches([{ 'ssid': 'lemonhead'}])
	rh.set_interval(30000)
elif sys.argv[2] == 'stop':
	rh = sched_scan_stop(ifidx, level)

err = rh.send()
print("scheduled scan %s: result=%d" % (sys.argv[2], err))
