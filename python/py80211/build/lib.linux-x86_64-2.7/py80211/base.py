##
# Module provide the core classes used in py80211.

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
import os
from abc import *

from netlink.capi import (NL_CB_DEFAULT, NL_CB_FINISH, NL_CB_ACK, NL_CB_CUSTOM,
			  NL_CB_SEQ_CHECK, NL_CB_VALID, NL_SKIP, NL_OK, NL_STOP,
			  NLA_NESTED, NLA_U64, NLA_U32, NLA_U16, NLA_U8,
			  NLA_FLAG, NLA_UNSPEC,
			  nl_socket_add_membership, nl_socket_drop_membership,
			  nlmsg_hdr, py_nla_parse_nested, nla_type,
			  nla_get_nested, nla_get_string, nla_get_u64,
			  nla_get_u32, nla_get_u16, nla_get_u8,
			  nla_data, nla_put_u32, nl_cb_alloc, py_nl_cb_set,
			  py_nl_cb_err, nl_connect, nl_send_auto_complete,
			  nl_recvmsgs, nl_socket_alloc_cb, nlmsg_alloc)
from netlink.genl.capi import (genlmsg_hdr, genl_ctrl_resolve, py_genlmsg_parse,
			       genlmsg_put, genl_ctrl_resolve_grp)
from netlink.core import (NETLINK_GENERIC, NLM_F_REQUEST, NLM_F_ACK)

import generated.defs as nl80211
from generated import strmap
import factory

NLA_NUL_STRING = NLA_NESTED + 2
NLA_BINARY = NLA_NESTED + 3
NLA_S8 = NLA_NESTED + 4
NLA_S16 = NLA_NESTED + 5
NLA_S32 = NLA_NESTED + 6
NLA_S64 = NLA_NESTED + 7

##
# Exception which is raised when netlink socket is already
# doing a transaction.
class AccessBusyError(Exception):
	pass

##
# Exception wich is raised when kernel-side returns an
# error.
class CommandFailedError(Exception):
	def __init__(self, msg, errno):
		self._cmd = genlmsg_hdr(nlmsg_hdr(msg)).cmd
		self._errno = errno

	def __str__(self):
		return "\n\t%s failed: %d (%s)" % (strmap.nl80211_commands2str[self._cmd], self._errno, os.strerror(-self._errno))

##
# Abstract class specifying the interface for object class which
# can be used to provide a custom netlink callback function.
class custom_handler(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def handle(self, msg, arg):
		pass

##
# This class provides socket connection to the nl80211 genl family.
class access80211(object):
	""" provide access to the nl80211 API """
	def __init__(self, level=NL_CB_DEFAULT):
		self._tx_cb = nl_cb_alloc(level)
		self._rx_cb = nl_cb_alloc(level)
		self._sock = nl_socket_alloc_cb(self._tx_cb)

		py_nl_cb_err(self._rx_cb, NL_CB_CUSTOM, self.error_handler, None)
		py_nl_cb_set(self._rx_cb, NL_CB_FINISH, NL_CB_CUSTOM, self.finish_handler, None)
		py_nl_cb_set(self._rx_cb, NL_CB_ACK, NL_CB_CUSTOM, self.ack_handler, None)

		nl_connect(self._sock, NETLINK_GENERIC)
		self._family = genl_ctrl_resolve(self._sock, 'nl80211')
		self._get_protocol_features()

	def _protocol_feature_handler(self, m, a):
                try:
                        e, attrs = py_genlmsg_parse(nlmsg_hdr(m), 0, nl80211.ATTR_MAX, None)
			if nl80211.ATTR_PROTOCOL_FEATURES in attrs:
				self._features = nla_get_u32(attrs[nl80211.ATTR_PROTOCOL_FEATURES])
                        return NL_SKIP
                except Exception as e:
                        (t,v,tb) = sys.exc_info()
                        print v.message
                        traceback.print_tb(tb)

		pass

	##
	# Obtain protocol features
	def _get_protocol_features(self):
		msg = self.alloc_genlmsg(nl80211.CMD_GET_PROTOCOL_FEATURES)
		self.busy = 1
		py_nl_cb_set(self._rx_cb, NL_CB_VALID, NL_CB_CUSTOM, self._protocol_feature_handler, None)
		self._send(msg)

	def has_protocol_feature(self, feat):
		if self._features & feat:
			return True
		return False

	##
	# Allocates a netlink message setup with genl header for nl80211 family.
	def alloc_genlmsg(self, cmd, flags=0):
		msg = nlmsg_alloc()
		genlmsg_put(msg, 0, 0, self._family, 0, flags, cmd, 0)
		return msg

	##
	# Send netlink message to the kernel and wait for response. The provided
	# handler will be called for NL_CB_VALID callback.
	def send(self, msg, handler):
		if not isinstance(handler, custom_handler):
			raise Exception("provided 'handler' is not a custom_handler instance")
		if self.busy == 1:
			raise AccessBusyError()
		self.busy = 1
		py_nl_cb_set(self._rx_cb, NL_CB_VALID, NL_CB_CUSTOM, handler.handle, None)
		self._send(msg)

	def _send(self, msg):
		try:
			nl_send_auto_complete(self._sock, msg)
			while self.busy > 0:
				nl_recvmsgs(self._sock, self._rx_cb)
		except Exception as e:
			if self.busy > 0:
				raise e
		if self.busy < 0:
			raise CommandFailedError(msg, self.busy)

	##
	# Function effectively disables sequence number check.
	def noseq(self, m, a):
		return NL_OK

	##
	# Disable sequence number checking, which is required for receiving
	# multicast notifications.
	def disable_seq_check(self):
		py_nl_cb_set(self._rx_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, self.noseq, None)

	##
	# Enable sequence number checking.
	def enalbe_seq_check(self):
		py_nl_cb_set(self._rx_cb, NL_CB_SEQ_CHECK, NL_CB_DEFAULT, None, None)

	##
	# Subscribe to the provided multicast group for notifications.
	def subscribe_multicast(self, mcname):
		mcid = genl_ctrl_resolve_grp(self._sock, 'nl80211', mcname)
		nl_socket_add_membership(self._sock, mcid)
		return mcid

	##
	# Unsubscribe from the provided multicast group.
	def drop_multicast(self, mcid):
		if isinstance(mcid, str):
			mcid = genl_ctrl_resolve_grp(self._sock, 'nl80211', mcid)
		nl_socket_drop_membership(self._sock, mcid)

	##
	# Property (GET) for obtaining the generic netlink family.
	@property
	def family(self):
		return self._family

	##
	# Default finish handler which clears the busy flag causing send() to
	# stop receiving and return.
	def finish_handler(self, m, a):
		self.busy = 0
		return NL_SKIP

	##
	# Defaul ack handler.
	def ack_handler(self, m, a):
		self.busy = 0
		return NL_STOP

	##
	# Default error handler passing error value in busy flag.
	def error_handler(self, err, a):
		self.busy = err.error
		return NL_STOP

##
# main object which deals with storing the attributes converting them to
# python objects as specified by provided policy and nest_attr_map. The
# nest_attr_map is a class variable to be provided by derived objects,
# which consists of tuple specifying class, maximum number of attributes and
# the policy of each nested attribute.
class nl80211_object(object):
	def __init__(self, attrs, policy=None):
		self._attrs = {}
		self._policy = policy
		if attrs != None:
			self.store_attrs(attrs)

	##
	# Creates a new instance for the nested attribute according
	# the nest_attr_map.
	def create_nested(self, attr, aid):
		try:
			if aid in self.nest_attr_map.keys():
				(nest_class, max_nest, nest_policy) = self.nest_attr_map[aid]
			e, nattr = py_nla_parse_nested(max_nest, attr, nest_policy)
			return factory.get_inst().create(nest_class, nattr, nest_policy)
		except Exception as e:
			return nla_type(attr)

	##
	# Creates a nested attribute list adding a new instance
	# for each nested element.
	def create_nested_list(self, attr_list, aid):
		nest_list = []
		for nest_element in nla_get_nested(attr_list):
			nest_obj = self.create_nested(nest_element, aid)
			if isinstance(nest_obj, nl80211_object):
				nest_obj.nla_type = nla_type(nest_element)
			nest_list.append(nest_obj)
		return nest_list

	##
	# Creates a list of attributes that are a basic type.
	def create_list(self, attr_list, pol):
		nest_list = []
		item_type = pol.list_type
		for item in nla_get_nested(attr_list):
			if item_type == NLA_NUL_STRING:
				nest_obj = nla_get_string(item)
			elif item_type == NLA_U64:
				nest_obj = nla_get_u64(item)
			elif item_type == NLA_U32:
				nest_obj = nla_get_u32(item)
			elif item_type == NLA_U16:
				nest_obj = nla_get_u16(item)
			elif item_type == NLA_U8:
				nest_obj = nla_get_u8(item)
			else:
				raise Exception("type (%d) not supported for list" % item_type)
			nest_list.append(nest_obj)
		return nest_list

	def create_map(self, map_attr, pol):
		nest_map = {}
		for key in nla_get_nested(map_attr):
			nest_list = self.create_list(key, pol)
			if len(nest_list) > 0:
				nest_map[nla_type(key)] = nest_list
		return nest_map

	##
	# Do a 2s complement sign conversion on attribute
	# which may be a list of values.
	def convert_sign(self, attr, pol):
		conv_tab = {
			NLA_U64: 0x8000000000000000,
			NLA_U32: 0x80000000,
			NLA_U16: 0x8000,
			NLA_U8: 0x80
		}
		pol_type = pol.type
		if pol.type == NLA_NESTED:
			pol_type = pol.list_type
		if not pol_type in conv_tab:
			raise Exception("invalid type (%d) for sign conversion" % pol_type)
		conv_check = conv_tab[pol_type]
		if pol.type != NLA_NESTED:
			if attr & conv_check:
				return -conv_check + (attr & (conv_check - 1))
		else:
			for aid in range(len(attr)):
				attr[aid] = -conv_check + (attr[aid] & (conv_check - 1))
		return attr

	##
	# Called after storing the netlink attributes. This allows doing any custom
	# post-processing of the netlink attributes by overriding this method.
	def post_store_attrs(self, attrs):
		pass

	##
	# In case of split dump we get certain attributes passed in
	# subsequent netlink messages and need to merge the result.
	def merge_nested_attrs(self, aid, nest):
		if not aid in self._attrs:
			self._attrs[aid] = nest
			return
		if not isinstance(nest, list):
			raise Exception("only 'list' instances supported: %s aid %d nest %s" % (type(self), aid, type(nest)))

		last = len(self._attrs[aid]) - 1
		last = self._attrs[aid][last]
		for n in nest:
			if n.nla_type != last.nla_type:
				self._attrs[aid].append(n)
				last = n
			else:
				for idx in n._attrs.keys():
					last.merge_nested_attrs(idx, n._attrs[idx])
	##
	# Stores the attributes using the appropriate nla_get function
	# according the provided policy.
	def store_attrs(self, attrs):
		for aid in attrs.keys():
			try:
				pol = self._policy[aid]
				if pol.type == NLA_S8:
					pol.type = NLA_U8
					pol.signed = True
				elif pol.type == NLA_S16:
					pol.type = NLA_U16
					pol.signed = True
				elif pol.type == NLA_S32:
					pol.type = NLA_U32
					pol.signed = True
				elif pol.type == NLA_S64:
					pol.type = NLA_U64
					pol.signed = True

				if pol.type == NLA_NUL_STRING:
					self._attrs[aid] = nla_get_string(attrs[aid])
				elif pol.type == NLA_U64:
					self._attrs[aid] = nla_get_u64(attrs[aid])
				elif pol.type == NLA_U32:
					self._attrs[aid] = nla_get_u32(attrs[aid])
				elif pol.type == NLA_U16:
					self._attrs[aid] = nla_get_u16(attrs[aid])
				elif pol.type == NLA_U8:
					self._attrs[aid] = nla_get_u8(attrs[aid])
				elif pol.type == NLA_FLAG:
					self._attrs[aid] = True
				elif pol.type == NLA_NESTED:
					if hasattr(pol, 'single') and pol.single:
						obj = self.create_nested(attrs[aid], aid)
					elif hasattr(pol, 'map') and pol.map:
						if not hasattr(pol, 'list_type'):
							raise Exception('need to specify "list_type" for map')
						obj = self.create_map(attrs[aid], pol)
					elif hasattr(pol, 'list_type'):
						obj = self.create_list(attrs[aid], pol)
					else:
						obj = self.create_nested_list(attrs[aid], aid)
					self.merge_nested_attrs(aid, obj)
				elif pol.type in [ NLA_BINARY, NLA_UNSPEC ]:
					self._attrs[aid] = nla_data(attrs[aid])
				if hasattr(pol, 'signed') and pol.signed:
					self._attrs[aid] = self.convert_sign(self._attrs[aid], pol)
			except Exception as e:
				print e.message
				self._attrs[aid] = nla_data(attrs[aid])
		self.post_store_attrs(attrs)

	##
	# Property (GET) for obtaining the attributes.
	@property
	def attrs(self):
		return self._attrs

##
# The managed object can be used for objects whose data is obtained
# using a specific command. The derived class needs to specify the
# NL80211 command (self._cmd) to use and implement abstract method
# put_obj_id() putting PHY, NETDEV, or WDEV as needed.
class nl80211_managed_object(nl80211_object, custom_handler):
	def __init__(self, access, attrs, policy=None):
		nl80211_object.__init__(self, attrs, policy)
		if access == None:
			self._access = access80211()
		else:
			self._access = access

	##
	# Property (GET) to obtain command.
	@property
	def objcmd(self):
		try:
			return self._cmd
		except Exception:
			raise Exception('class need to define _cmd attribute')

	##
	# Abstract method to fill object identifier in netlink message.
	@abstractmethod
	def put_obj_id(m):
		pass

	##
	# Refresh object data by sending a new netlink message to the kernel.
	def refresh(self):
		m = self._access.alloc_genlmsg(self.objcmd, NLM_F_REQUEST | NLM_F_ACK)
		self.put_obj_id(m)
		self._access.send(m, self)

	##
	# Valid handler parsing the response(s) and store the attributes.
	def handle(self, msg, arg):
		try:
			e, attrs = py_genlmsg_parse(nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			self.store_attrs(attrs)
			return NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)

class nl80211_cmd_base(custom_handler):
	def __init__(self, ifidx, level=NL_CB_DEFAULT):
		self._access = access80211(level)
		self._cmd = None
		self._ifidx = ifidx

	def _prepare_cmd(self):
		if hasattr(self, '_nl_msg'):
			return
		if self._cmd == None:
			raise Exception("sub-class must set _cmd")

		flags = NLM_F_REQUEST | NLM_F_ACK
		self._nl_msg = self._access.alloc_genlmsg(self._cmd, flags)

	def _add_attrs(self):
		nla_put_u32(self._nl_msg, nl80211.ATTR_IFINDEX, self._ifidx)

	def nl_msg(self):
		self._prepare_cmd()
		return self._nl_msg

	def send(self):
		self._prepare_cmd()
		self._add_attrs()
		return self._access.send(self._nl_msg, self)

