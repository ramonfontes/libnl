# This file was automatically generated by SWIG (http://www.swig.org).
# Version 4.0.1
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _capi
else:
    import _capi

try:
    import builtins as __builtin__
except ImportError:
    import __builtin__

_swig_new_instance_method = _capi.SWIG_PyInstanceMethod_New
_swig_new_static_method = _capi.SWIG_PyStaticMethod_New

def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)


def _swig_setattr_nondynamic_instance_variable(set):
    def set_instance_attr(self, name, value):
        if name == "thisown":
            self.this.own(value)
        elif name == "this":
            set(self, name, value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name), property):
            set(self, name, value)
        else:
            raise AttributeError("You cannot add instance attributes to %s" % self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):
    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError("You cannot add class attributes to %s" % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


alloc_dump_params = _capi.alloc_dump_params
free_dump_params = _capi.free_dump_params
NL_DUMP_LINE = _capi.NL_DUMP_LINE
NL_DUMP_DETAILS = _capi.NL_DUMP_DETAILS
NL_DUMP_STATS = _capi.NL_DUMP_STATS
__NL_DUMP_MAX = _capi.__NL_DUMP_MAX
class nl_dump_params(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    dp_type = property(_capi.nl_dump_params_dp_type_get, _capi.nl_dump_params_dp_type_set)
    dp_prefix = property(_capi.nl_dump_params_dp_prefix_get, _capi.nl_dump_params_dp_prefix_set)
    dp_print_index = property(_capi.nl_dump_params_dp_print_index_get, _capi.nl_dump_params_dp_print_index_set)
    dp_dump_msgtype = property(_capi.nl_dump_params_dp_dump_msgtype_get, _capi.nl_dump_params_dp_dump_msgtype_set)
    dp_cb = property(_capi.nl_dump_params_dp_cb_get, _capi.nl_dump_params_dp_cb_set)
    dp_nl_cb = property(_capi.nl_dump_params_dp_nl_cb_get, _capi.nl_dump_params_dp_nl_cb_set)
    dp_data = property(_capi.nl_dump_params_dp_data_get, _capi.nl_dump_params_dp_data_set)
    dp_fd = property(_capi.nl_dump_params_dp_fd_get, _capi.nl_dump_params_dp_fd_set)
    dp_buf = property(_capi.nl_dump_params_dp_buf_get, _capi.nl_dump_params_dp_buf_set)
    dp_buflen = property(_capi.nl_dump_params_dp_buflen_get, _capi.nl_dump_params_dp_buflen_set)
    dp_pre_dump = property(_capi.nl_dump_params_dp_pre_dump_get, _capi.nl_dump_params_dp_pre_dump_set)
    dp_ivar = property(_capi.nl_dump_params_dp_ivar_get, _capi.nl_dump_params_dp_ivar_set)
    dp_line = property(_capi.nl_dump_params_dp_line_get, _capi.nl_dump_params_dp_line_set)
    __swig_destroy__ = _capi.delete_nl_dump_params

# Register nl_dump_params in _capi:
_capi.nl_dump_params_swigregister(nl_dump_params)

if_nametoindex = _capi.if_nametoindex
nl_geterror = _capi.nl_geterror
nl_cancel_down_bytes = _capi.nl_cancel_down_bytes
nl_cancel_down_bits = _capi.nl_cancel_down_bits
nl_rate2str = _capi.nl_rate2str
nl_cancel_down_us = _capi.nl_cancel_down_us
nl_size2int = _capi.nl_size2int
nl_size2str = _capi.nl_size2str
nl_prob2int = _capi.nl_prob2int
nl_get_user_hz = _capi.nl_get_user_hz
nl_us2ticks = _capi.nl_us2ticks
nl_ticks2us = _capi.nl_ticks2us
nl_str2msec = _capi.nl_str2msec
nl_msec2str = _capi.nl_msec2str
nl_llproto2str = _capi.nl_llproto2str
nl_str2llproto = _capi.nl_str2llproto
nl_ether_proto2str = _capi.nl_ether_proto2str
nl_str2ether_proto = _capi.nl_str2ether_proto
nl_ip_proto2str = _capi.nl_ip_proto2str
nl_str2ip_proto = _capi.nl_str2ip_proto
nl_new_line = _capi.nl_new_line
nl_dump = _capi.nl_dump
nl_dump_line = _capi.nl_dump_line
nl_connect = _capi.nl_connect
nl_close = _capi.nl_close
nl_socket_alloc = _capi.nl_socket_alloc
nl_socket_alloc_cb = _capi.nl_socket_alloc_cb
nl_socket_free = _capi.nl_socket_free
nl_socket_get_local_port = _capi.nl_socket_get_local_port
nl_socket_set_local_port = _capi.nl_socket_set_local_port
nl_socket_get_peer_port = _capi.nl_socket_get_peer_port
nl_socket_set_peer_port = _capi.nl_socket_set_peer_port
nl_socket_get_peer_groups = _capi.nl_socket_get_peer_groups
nl_socket_set_peer_groups = _capi.nl_socket_set_peer_groups
nl_socket_set_buffer_size = _capi.nl_socket_set_buffer_size
nl_socket_set_cb = _capi.nl_socket_set_cb
nl_socket_add_membership = _capi.nl_socket_add_membership
nl_socket_drop_membership = _capi.nl_socket_drop_membership
nl_send_auto_complete = _capi.nl_send_auto_complete
nl_recvmsgs = _capi.nl_recvmsgs
nlmsg_size = _capi.nlmsg_size
nlmsg_total_size = _capi.nlmsg_total_size
nlmsg_padlen = _capi.nlmsg_padlen
nlmsg_data = _capi.nlmsg_data
nlmsg_datalen = _capi.nlmsg_datalen
nlmsg_tail = _capi.nlmsg_tail
nlmsg_attrdata = _capi.nlmsg_attrdata
nlmsg_attrlen = _capi.nlmsg_attrlen
nlmsg_valid_hdr = _capi.nlmsg_valid_hdr
nlmsg_ok = _capi.nlmsg_ok
nlmsg_next = _capi.nlmsg_next
nlmsg_parse = _capi.nlmsg_parse
nlmsg_find_attr = _capi.nlmsg_find_attr
nlmsg_validate = _capi.nlmsg_validate
nlmsg_alloc = _capi.nlmsg_alloc
nlmsg_alloc_size = _capi.nlmsg_alloc_size
nlmsg_alloc_simple = _capi.nlmsg_alloc_simple
nlmsg_set_default_size = _capi.nlmsg_set_default_size
nlmsg_inherit = _capi.nlmsg_inherit
nlmsg_convert = _capi.nlmsg_convert
nlmsg_reserve = _capi.nlmsg_reserve
nlmsg_append = _capi.nlmsg_append
nlmsg_expand = _capi.nlmsg_expand
nlmsg_put = _capi.nlmsg_put
nlmsg_hdr = _capi.nlmsg_hdr
nlmsg_get = _capi.nlmsg_get
nlmsg_free = _capi.nlmsg_free
nlmsg_set_proto = _capi.nlmsg_set_proto
nlmsg_get_proto = _capi.nlmsg_get_proto
nlmsg_get_max_size = _capi.nlmsg_get_max_size
nlmsg_set_src = _capi.nlmsg_set_src
nlmsg_get_src = _capi.nlmsg_get_src
nlmsg_set_dst = _capi.nlmsg_set_dst
nlmsg_get_dst = _capi.nlmsg_get_dst
nlmsg_set_creds = _capi.nlmsg_set_creds
nlmsg_get_creds = _capi.nlmsg_get_creds
nl_nlmsgtype2str = _capi.nl_nlmsgtype2str
nl_str2nlmsgtype = _capi.nl_str2nlmsgtype
nl_nlmsg_flags2str = _capi.nl_nlmsg_flags2str
nl_msg_parse = _capi.nl_msg_parse
nl_msg_dump = _capi.nl_msg_dump
cast_obj = _capi.cast_obj
object_alloc_name = _capi.object_alloc_name
nl_object_alloc = _capi.nl_object_alloc
nl_object_free = _capi.nl_object_free
nl_object_clone = _capi.nl_object_clone
nl_object_get = _capi.nl_object_get
nl_object_put = _capi.nl_object_put
nl_object_shared = _capi.nl_object_shared
nl_object_dump_buf = _capi.nl_object_dump_buf
nl_object_dump = _capi.nl_object_dump
nl_object_identical = _capi.nl_object_identical
nl_object_diff = _capi.nl_object_diff
nl_object_match_filter = _capi.nl_object_match_filter
nl_object_attrs2str = _capi.nl_object_attrs2str
nl_object_attr_list = _capi.nl_object_attr_list
nl_object_mark = _capi.nl_object_mark
nl_object_unmark = _capi.nl_object_unmark
nl_object_is_marked = _capi.nl_object_is_marked
nl_object_get_refcnt = _capi.nl_object_get_refcnt
alloc_cache_name = _capi.alloc_cache_name
alloc_cache_mngr = _capi.alloc_cache_mngr
cache_mngr_add = _capi.cache_mngr_add
nl_cache_nitems = _capi.nl_cache_nitems
nl_cache_nitems_filter = _capi.nl_cache_nitems_filter
nl_cache_get_ops = _capi.nl_cache_get_ops
nl_cache_get_first = _capi.nl_cache_get_first
nl_cache_get_last = _capi.nl_cache_get_last
nl_cache_get_next = _capi.nl_cache_get_next
nl_cache_get_prev = _capi.nl_cache_get_prev
nl_cache_alloc = _capi.nl_cache_alloc
nl_cache_subset = _capi.nl_cache_subset
nl_cache_clear = _capi.nl_cache_clear
nl_cache_free = _capi.nl_cache_free
nl_cache_add = _capi.nl_cache_add
nl_cache_parse_and_add = _capi.nl_cache_parse_and_add
nl_cache_remove = _capi.nl_cache_remove
nl_cache_refill = _capi.nl_cache_refill
nl_cache_pickup = _capi.nl_cache_pickup
nl_cache_resync = _capi.nl_cache_resync
nl_cache_include = _capi.nl_cache_include
nl_cache_set_arg1 = _capi.nl_cache_set_arg1
nl_cache_set_arg2 = _capi.nl_cache_set_arg2
nl_cache_is_empty = _capi.nl_cache_is_empty
nl_cache_search = _capi.nl_cache_search
nl_cache_mark_all = _capi.nl_cache_mark_all
nl_cache_dump = _capi.nl_cache_dump
nl_cache_dump_filter = _capi.nl_cache_dump_filter
nl_cache_foreach = _capi.nl_cache_foreach
nl_cache_foreach_filter = _capi.nl_cache_foreach_filter
nl_cache_ops_lookup = _capi.nl_cache_ops_lookup
nl_cache_ops_associate = _capi.nl_cache_ops_associate
nl_msgtype_lookup = _capi.nl_msgtype_lookup
nl_cache_ops_foreach = _capi.nl_cache_ops_foreach
nl_cache_mngt_register = _capi.nl_cache_mngt_register
nl_cache_mngt_unregister = _capi.nl_cache_mngt_unregister
nl_cache_mngt_provide = _capi.nl_cache_mngt_provide
nl_cache_mngt_unprovide = _capi.nl_cache_mngt_unprovide
nl_cache_mngt_require = _capi.nl_cache_mngt_require
NL_AUTO_PROVIDE = _capi.NL_AUTO_PROVIDE
nl_cache_mngr_get_fd = _capi.nl_cache_mngr_get_fd
nl_cache_mngr_poll = _capi.nl_cache_mngr_poll
nl_cache_mngr_data_ready = _capi.nl_cache_mngr_data_ready
nl_cache_mngr_free = _capi.nl_cache_mngr_free
addr_parse = _capi.addr_parse
nl_addr_alloc = _capi.nl_addr_alloc
nl_addr_alloc_attr = _capi.nl_addr_alloc_attr
nl_addr_build = _capi.nl_addr_build
nl_addr_clone = _capi.nl_addr_clone
nl_addr_get = _capi.nl_addr_get
nl_addr_put = _capi.nl_addr_put
nl_addr_shared = _capi.nl_addr_shared
nl_addr_cmp = _capi.nl_addr_cmp
nl_addr_cmp_prefix = _capi.nl_addr_cmp_prefix
nl_addr_iszero = _capi.nl_addr_iszero
nl_addr_valid = _capi.nl_addr_valid
nl_addr_guess_family = _capi.nl_addr_guess_family
nl_addr_fill_sockaddr = _capi.nl_addr_fill_sockaddr
nl_addr_info = _capi.nl_addr_info
nl_addr_resolve = _capi.nl_addr_resolve
nl_addr_set_family = _capi.nl_addr_set_family
nl_addr_get_family = _capi.nl_addr_get_family
nl_addr_set_binary_addr = _capi.nl_addr_set_binary_addr
nl_addr_get_binary_addr = _capi.nl_addr_get_binary_addr
nl_addr_get_len = _capi.nl_addr_get_len
nl_addr_set_prefixlen = _capi.nl_addr_set_prefixlen
nl_addr_get_prefixlen = _capi.nl_addr_get_prefixlen
nl_af2str = _capi.nl_af2str
nl_str2af = _capi.nl_str2af
nl_addr2str = _capi.nl_addr2str
NL_OK = _capi.NL_OK
NL_SKIP = _capi.NL_SKIP
NL_STOP = _capi.NL_STOP
NL_CB_DEFAULT = _capi.NL_CB_DEFAULT
NL_CB_VERBOSE = _capi.NL_CB_VERBOSE
NL_CB_DEBUG = _capi.NL_CB_DEBUG
NL_CB_CUSTOM = _capi.NL_CB_CUSTOM
__NL_CB_KIND_MAX = _capi.__NL_CB_KIND_MAX
NL_CB_VALID = _capi.NL_CB_VALID
NL_CB_FINISH = _capi.NL_CB_FINISH
NL_CB_OVERRUN = _capi.NL_CB_OVERRUN
NL_CB_SKIPPED = _capi.NL_CB_SKIPPED
NL_CB_ACK = _capi.NL_CB_ACK
NL_CB_MSG_IN = _capi.NL_CB_MSG_IN
NL_CB_MSG_OUT = _capi.NL_CB_MSG_OUT
NL_CB_INVALID = _capi.NL_CB_INVALID
NL_CB_SEQ_CHECK = _capi.NL_CB_SEQ_CHECK
NL_CB_SEND_ACK = _capi.NL_CB_SEND_ACK
NL_CB_DUMP_INTR = _capi.NL_CB_DUMP_INTR
__NL_CB_TYPE_MAX = _capi.__NL_CB_TYPE_MAX
nl_cb_alloc = _capi.nl_cb_alloc
nl_cb_clone = _capi.nl_cb_clone
class nlmsgerr(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    error = property(_capi.nlmsgerr_error_get, _capi.nlmsgerr_error_set)
    __swig_destroy__ = _capi.delete_nlmsgerr

# Register nlmsgerr in _capi:
_capi.nlmsgerr_swigregister(nlmsgerr)

py_nl_cb_clone = _capi.py_nl_cb_clone
py_nl_cb_put = _capi.py_nl_cb_put
py_nl_cb_set = _capi.py_nl_cb_set
py_nl_cb_set_all = _capi.py_nl_cb_set_all
py_nl_cb_err = _capi.py_nl_cb_err
nla_data = _capi.nla_data
nla_type = _capi.nla_type
nla_put = _capi.nla_put
nla_get_u8 = _capi.nla_get_u8
nla_put_u8 = _capi.nla_put_u8
nla_get_u16 = _capi.nla_get_u16
nla_put_u16 = _capi.nla_put_u16
nla_get_u32 = _capi.nla_get_u32
nla_put_u32 = _capi.nla_put_u32
nla_get_u64 = _capi.nla_get_u64
nla_put_u64 = _capi.nla_put_u64
nla_get_string = _capi.nla_get_string
nla_strdup = _capi.nla_strdup
nla_put_string = _capi.nla_put_string
nla_get_flag = _capi.nla_get_flag
nla_put_flag = _capi.nla_put_flag
nla_get_msecs = _capi.nla_get_msecs
nla_put_msecs = _capi.nla_put_msecs
nla_put_nested = _capi.nla_put_nested
nla_nest_start = _capi.nla_nest_start
nla_nest_end = _capi.nla_nest_end
py_nla_parse_nested = _capi.py_nla_parse_nested
nla_get_nested = _capi.nla_get_nested
NLA_UNSPEC = _capi.NLA_UNSPEC
NLA_U8 = _capi.NLA_U8
NLA_U16 = _capi.NLA_U16
NLA_U32 = _capi.NLA_U32
NLA_U64 = _capi.NLA_U64
NLA_STRING = _capi.NLA_STRING
NLA_FLAG = _capi.NLA_FLAG
NLA_MSECS = _capi.NLA_MSECS
NLA_NESTED = _capi.NLA_NESTED
__NLA_TYPE_MAX = _capi.__NLA_TYPE_MAX
class nla_policy(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    type = property(_capi.nla_policy_type_get, _capi.nla_policy_type_set)
    minlen = property(_capi.nla_policy_minlen_get, _capi.nla_policy_minlen_set)
    maxlen = property(_capi.nla_policy_maxlen_get, _capi.nla_policy_maxlen_set)
    __swig_destroy__ = _capi.delete_nla_policy

# Register nla_policy in _capi:
_capi.nla_policy_swigregister(nla_policy)

nla_policy_array = _capi.nla_policy_array

