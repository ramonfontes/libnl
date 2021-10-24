##
# Module providing info retrieval of wiphy objects.

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
			  NLA_FLAG, NLA_U32, NLA_U16, NLA_U8, NLA_NESTED,
			  NLA_UNSPEC, nla_get_u32, nla_put_u32, nla_put_flag,
			  NL_CB_DEFAULT, NL_SKIP)
from netlink.core import NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP
from netlink.genl.capi import py_genlmsg_parse
from .generated import defs as nl80211

from .generated.policy import nl80211_policy
from .base import *
from .factory import *

rate_policy = nla_policy_array(nl80211.BITRATE_ATTR_MAX + 1)
rate_policy[nl80211.BITRATE_ATTR_RATE].type = NLA_U32
rate_policy[nl80211.BITRATE_ATTR_2GHZ_SHORTPREAMBLE].type = NLA_FLAG

class wiphy_rate(nl80211_object):
	pass

freq_policy = nla_policy_array(nl80211.FREQUENCY_ATTR_MAX + 1)
freq_policy[nl80211.FREQUENCY_ATTR_FREQ].type = NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_DISABLED].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_IBSS].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_IR].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_RADAR].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_MAX_TX_POWER].type = NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_NO_HT40_MINUS].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_HT40_PLUS].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_80MHZ].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_160MHZ].type = NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_DFS_STATE].type = NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_DFS_TIME].type = NLA_U32

class wiphy_freq(nl80211_object):
	pass

band_policy = nla_policy_array(nl80211.BAND_ATTR_MAX + 1)
band_policy[nl80211.BAND_ATTR_FREQS].type = NLA_NESTED
band_policy[nl80211.BAND_ATTR_RATES].type = NLA_NESTED
band_policy[nl80211.BAND_ATTR_HT_MCS_SET].type = NLA_UNSPEC
band_policy[nl80211.BAND_ATTR_HT_CAPA].type = NLA_U16
band_policy[nl80211.BAND_ATTR_HT_AMPDU_FACTOR].type = NLA_U8
band_policy[nl80211.BAND_ATTR_HT_AMPDU_DENSITY].type = NLA_U8
band_policy[nl80211.BAND_ATTR_VHT_MCS_SET].type = NLA_UNSPEC
band_policy[nl80211.BAND_ATTR_VHT_CAPA].type = NLA_U32

class wiphy_band(nl80211_object):
	nest_attr_map = {
		nl80211.BAND_ATTR_FREQS: (wiphy_freq, len(freq_policy), freq_policy),
		nl80211.BAND_ATTR_RATES: (wiphy_rate, len(rate_policy), rate_policy)
	}

iface_limit_policy = nla_policy_array(nl80211.NUM_NL80211_IFACE_LIMIT)
iface_limit_policy[nl80211.IFACE_LIMIT_TYPES].type = NLA_NESTED
iface_limit_policy[nl80211.IFACE_LIMIT_MAX].type = NLA_U32

class wiphy_iface_limit(nl80211_object):
	pass

iface_combination_policy = nla_policy_array(nl80211.NUM_NL80211_IFACE_COMB)
iface_combination_policy[nl80211.IFACE_COMB_LIMITS].type = NLA_NESTED
iface_combination_policy[nl80211.IFACE_COMB_MAXNUM].type = NLA_U32
iface_combination_policy[nl80211.IFACE_COMB_STA_AP_BI_MATCH].type = NLA_FLAG
iface_combination_policy[nl80211.IFACE_COMB_NUM_CHANNELS].type = NLA_U32
iface_combination_policy[nl80211.IFACE_COMB_RADAR_DETECT_WIDTHS].type = NLA_U32

class wiphy_iface_combo(nl80211_object):
	nest_attr_map = {
		nl80211.IFACE_COMB_LIMITS: (wiphy_iface_limit, len(iface_limit_policy), iface_limit_policy),
	}

wowlan_policy = nla_policy_array(nl80211.NUM_NL80211_WOWLAN_TRIG)
wowlan_policy[nl80211.WOWLAN_TRIG_ANY].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_DISCONNECT].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_MAGIC_PKT].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_PKT_PATTERN].minlen = 16
wowlan_policy[nl80211.WOWLAN_TRIG_GTK_REKEY_SUPPORTED].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_GTK_REKEY_FAILURE].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_EAP_IDENT_REQUEST].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_4WAY_HANDSHAKE].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_RFKILL_RELEASE].type = NLA_FLAG
wowlan_policy[nl80211.WOWLAN_TRIG_NET_DETECT].type = NLA_U32

class wowlan_trigger_support(nl80211_object):
	pass

class wiphy(nl80211_managed_object):
	nest_attr_map = {
		nl80211.ATTR_WIPHY_BANDS: (wiphy_band, len(band_policy), band_policy),
		nl80211.ATTR_INTERFACE_COMBINATIONS: (wiphy_iface_combo, len(iface_combination_policy), iface_combination_policy),
		nl80211.ATTR_WOWLAN_TRIGGERS_SUPPORTED: (wowlan_trigger_support, len(wowlan_policy), wowlan_policy)
	}
	_cmd = nl80211.CMD_GET_WIPHY
	def __init__(self, access, attrs):
		nl80211_managed_object.__init__(self, access, attrs, nl80211_policy)
		self._phynum = nla_get_u32(attrs[nl80211.ATTR_WIPHY])

	def post_store_attrs(self, attrs):
		# cipher suites are actually C-array of u32 so using struct module
		# to obtain the list of cipher suites.
		if not nl80211.ATTR_CIPHER_SUITES in attrs:
			return
		data = self.attrs[nl80211.ATTR_CIPHER_SUITES]
		fmt = int(len(data) / 4) * 'i'
		self.attrs[nl80211.ATTR_CIPHER_SUITES] = list(struct.unpack(fmt, data))

	def put_obj_id(self, msg):
		nla_put_u32(msg._msg, nl80211.ATTR_WIPHY, self.phynum)
		nla_put_flag(msg._msg, nl80211.ATTR_SPLIT_WIPHY_DUMP)

	@property
	def phynum(self):
		return self._phynum

	def __hash__(self):
		return self._phynum

	def is_feature_supported(self, feature):
		flags = self.attrs[nl80211.ATTR_FEATURE_FLAGS]
		return (flags & feature) != 0

	def is_cmd_supported(self, cmd):
		return cmd in self.attrs[nl80211.ATTR_SUPPORTED_COMMANDS]

class wiphy_list(custom_handler):
	def __init__(self, kind=NL_CB_DEFAULT):
		self._wiphy = {}
		a = access80211(kind)
		flags = NLM_F_REQUEST | NLM_F_ACK
		split_wiphy = a.has_protocol_feature(nl80211.PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
		if split_wiphy:
			flags |= NLM_F_DUMP
		m = a.alloc_genlmsg(nl80211.CMD_GET_WIPHY, flags)
		if split_wiphy:
			nla_put_flag(m, nl80211.ATTR_SPLIT_WIPHY_DUMP)
		self._access = a
		a.send(m, self)

	def __iter__(self):
		return iter(self._wiphy.values())

	def handle(self, msg, arg):
		try:
			e, attrs = py_genlmsg_parse(nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			if nl80211.ATTR_WIPHY in attrs:
				phynum = nla_get_u32(attrs[nl80211.ATTR_WIPHY])
				if phynum in self._wiphy.keys():
					self._wiphy[phynum].store_attrs(attrs)
				else:
					phy = get_inst().create(wiphy, self._access, attrs)
					self._wiphy[phy.phynum] = phy
			return NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print(v.message)
			traceback.print_tb(tb)

	@property
	def wiphys(self):
		return self._wiphy.values()
