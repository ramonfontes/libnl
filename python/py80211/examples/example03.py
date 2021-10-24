from py80211.scan import *
from py80211.station import *
import netlink.capi as nl
from py80211.cli import bss_info, sta_info
import sys

ifidx = nl.if_nametoindex(sys.argv[1])
bl = bss_list(ifidx)

sta = station_list(ifidx)

bss = bl.find_status_bss()
if bss and bss.attrs[nl80211.BSS_STATUS] == nl80211.BSS_STATUS_ASSOCIATED:
	s = station(ifidx, bss.attrs[nl80211.BSS_BSSID], bl._access)
	sta_info_attrs = s.attrs[nl80211.ATTR_STA_INFO]
	print(sta_info_attrs)
	print(bss_info(bss))