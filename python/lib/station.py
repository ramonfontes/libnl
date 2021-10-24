##
# Module providing station information

#
# Copyright 2015 Arend van Spriel <aspriel@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
import sys
import traceback
import struct

from netlink.capi import (nla_policy_array,
			  NLA_FLAG, NLA_U8, NLA_U16, NLA_U32, NLA_U64, NLA_NESTED,
			  nla_put_u32, nla_put, NL_CB_DEFAULT, nlmsg_hdr, NL_SKIP)
from netlink.core import NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP
from netlink.genl.capi import py_genlmsg_parse
from .generated import defs as nl

from .generated.policy import *
from .base import access80211, nl80211_object, nl80211_managed_object, custom_handler
from .factory import *

bss_param_policy = nla_policy_array(nl.STA_BSS_PARAM_MAX + 1)
bss_param_policy[nl.STA_BSS_PARAM_CTS_PROT].type = NLA_FLAG
bss_param_policy[nl.STA_BSS_PARAM_SHORT_PREAMBLE].type = NLA_FLAG
bss_param_policy[nl.STA_BSS_PARAM_SHORT_SLOT_TIME].type = NLA_FLAG
bss_param_policy[nl.STA_BSS_PARAM_DTIM_PERIOD].type = NLA_U8
bss_param_policy[nl.STA_BSS_PARAM_BEACON_INTERVAL].type = NLA_U16

class bss_param(nl80211_object):
	pass

bitrate_policy = nla_policy_array(nl.RATE_INFO_MAX + 1)
bitrate_policy[nl.RATE_INFO_BITRATE].type = NLA_U16
bitrate_policy[nl.RATE_INFO_BITRATE32].type = NLA_U32
bitrate_policy[nl.RATE_INFO_MCS].type = NLA_U8
bitrate_policy[nl.RATE_INFO_40_MHZ_WIDTH].type = NLA_FLAG
bitrate_policy[nl.RATE_INFO_SHORT_GI].type = NLA_FLAG

class bitrate(nl80211_object):
	pass

stats_policy = nla_policy_array(nl.STA_INFO_MAX + 1)
stats_policy[nl.STA_INFO_INACTIVE_TIME].type = NLA_U32
stats_policy[nl.STA_INFO_RX_BYTES].type = NLA_U32
stats_policy[nl.STA_INFO_TX_BYTES].type = NLA_U32
stats_policy[nl.STA_INFO_RX_PACKETS].type = NLA_U32
stats_policy[nl.STA_INFO_TX_PACKETS].type = NLA_U32
stats_policy[nl.STA_INFO_SIGNAL].type = NLA_U8
stats_policy[nl.STA_INFO_SIGNAL].signed = True
stats_policy[nl.STA_INFO_SIGNAL_AVG].type = NLA_U8
stats_policy[nl.STA_INFO_SIGNAL_AVG].signed = True
stats_policy[nl.STA_INFO_T_OFFSET].type = NLA_U64
stats_policy[nl.STA_INFO_TX_BITRATE].type = NLA_NESTED
stats_policy[nl.STA_INFO_TX_BITRATE].single = True
stats_policy[nl.STA_INFO_RX_BITRATE].type = NLA_NESTED
stats_policy[nl.STA_INFO_RX_BITRATE].single = True
stats_policy[nl.STA_INFO_LLID].type = NLA_U16
stats_policy[nl.STA_INFO_PLID].type = NLA_U16
stats_policy[nl.STA_INFO_PLINK_STATE].type = NLA_U8
stats_policy[nl.STA_INFO_TX_RETRIES].type = NLA_U32
stats_policy[nl.STA_INFO_TX_FAILED].type = NLA_U32
stats_policy[nl.STA_INFO_STA_FLAGS].minlen = 8
stats_policy[nl.STA_INFO_LOCAL_PM].type = NLA_U32
stats_policy[nl.STA_INFO_PEER_PM].type = NLA_U32
stats_policy[nl.STA_INFO_NONPEER_PM].type = NLA_U32
stats_policy[nl.STA_INFO_CHAIN_SIGNAL].type = NLA_NESTED
stats_policy[nl.STA_INFO_CHAIN_SIGNAL].list_type = NLA_U8
stats_policy[nl.STA_INFO_CHAIN_SIGNAL].signed = True
stats_policy[nl.STA_INFO_CHAIN_SIGNAL_AVG].type = NLA_NESTED
stats_policy[nl.STA_INFO_CHAIN_SIGNAL_AVG].list_type = NLA_U8
stats_policy[nl.STA_INFO_CHAIN_SIGNAL_AVG].signed = True
stats_policy[nl.STA_INFO_RX_BYTES64].type = NLA_U64
stats_policy[nl.STA_INFO_TX_BYTES64].type = NLA_U64
stats_policy[nl.STA_INFO_BEACON_LOSS].type = NLA_U32
stats_policy[nl.STA_INFO_CONNECTED_TIME].type = NLA_U32
stats_policy[nl.STA_INFO_BSS_PARAM].type = NLA_NESTED
stats_policy[nl.STA_INFO_BSS_PARAM].single = True

class station_stats(nl80211_object):

	nest_attr_map = {
		nl.STA_INFO_TX_BITRATE: (bitrate, len(bitrate_policy), bitrate_policy),
		nl.STA_INFO_RX_BITRATE: (bitrate, len(bitrate_policy), bitrate_policy),
		nl.STA_INFO_BSS_PARAM: (bss_param, len(bss_param_policy), bss_param_policy)
	}

	def __init__(self, attrs, policy):
		print("aaaaaaa")
		nl_object.__init__(self, attrs, policy)

	def post_store_attrs(self, attrs):
		print(attrs)
		print("aaaaaaaaaaaaa")
		if nl.STA_INFO_STA_FLAGS in attrs:
			flags = get_inst().create(sta_flags, self.attrs[nl.STA_INFO_STA_FLAGS])
			self._attrs[nl.STA_INFO_STA_FLAGS] = flags

class sta_flags(object):
	def __init__(self, bytes):
		if len(bytes) < 8:
			raise Exception("not enough sta_flags bytes")
		self.fmask, self.fset = struct.unpack('ii', bytes)

class station(nl80211_managed_object):
	nest_attr_map = {
		nl.ATTR_STA_INFO: (station_stats, len(stats_policy), stats_policy)
	}
	_cmd = nl.CMD_GET_STATION
	def __init__(self, ifidx, mac, access=None, attrs=None):
		nl80211_managed_object.__init__(self, access, attrs, nl80211_policy)
		self._ifidx = ifidx
		if nl.ATTR_MAC in self.attrs:
			self._mac = self.attrs[nl.ATTR_MAC]
		elif mac == None:
			raise Exception("need to provide a mac address")
		elif not isinstance(mac, bytearray):
			raise Exception("mac address must be bytearray")
		else:
			self._mac = mac
			self.refresh()

	def put_obj_id(self, msg):
		nla_put_u32(msg, nl.ATTR_IFINDEX, self._ifidx)
		nla_put(msg, nl.ATTR_MAC, self._mac)

	def __hash__(self):
		mac_hash = self._mac[1:3] + self._mac[4:6]
		return struct.unpack('i', mac_hash)[0]

	def __cmp__(self, other):
		return (self.__hash__() - other.__hash__()) & sys.maxint

class station_list(custom_handler):
	def __init__(self, ifidx, access=None, kind=NL_CB_DEFAULT):
		self._station = []
		self._ifidx = ifidx
		if access == None:
			access = access80211(kind)
		flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP
		m = access.alloc_genlmsg(nl.CMD_GET_STATION, flags)
		nla_put_u32(m, nl.ATTR_IFINDEX, ifidx)
		self._access = access
		access.send(m, self)

	def __iter__(self):
		return iter(self._station)

	def store_station(self, sta):
		for s in self._station:
			if s == sta:
				s._attrs = sta._attrs
				return
		self._station.append(sta)

	def handle(self, msg, arg):
		try:
			e, attrs = py_genlmsg_parse(nlmsg_hdr(msg), 0, nl.ATTR_MAX, None)

			if not nl.ATTR_STA_AID in attrs:
				return
			e, nattrs = py_nla_parse_nested(len(stats_policy), attrs[nl80211.ATTR_STA_AID], stats_policy)


			sta = get_inst().create(station, self._ifidx, None, self._access, attrs)
			s = self.store_station(sta)
			return NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print(message)
			traceback.print_tb(tb)
