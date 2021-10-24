#
# nl80211 enumeration extractor script
#
# Copyright 2013 Arend van Spriel <aspriel@gmail.com>
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
from pycparser import parse_file, c_ast
import argparse
import subprocess
import os.path
import os
import sys
import re

EXTRACT_HEADER = 'extract.h'
hdrpath = 'include|uapi|linux|nl80211.h'.replace('|', os.sep)
srcpath = 'net|wireless|nl80211.i'.replace('|', os.sep)

def extract_prepare(srcdir):
	global hdrpath, srcpath

	gitdir = os.path.join(srcdir, '.git')
	if not os.path.exists(os.path.join(srcdir, '.git')):
		sys.stderr.write('warning: could not find git revision info in source tree\n')
		revinfo = 'unknown'
	else:
		revinfo = subprocess.check_output(['git', '--git-dir=%s' % gitdir, 'describe'])
		sys.stdout.write('source tree on revision %s\n' % revinfo)

	if not os.path.exists(os.path.join(srcdir, hdrpath)):
		sys.stderr.write('error: source tree does not contain \'%s\'\n' % hdrpath)
		sys.exit(1)

	cppath = os.path.join(srcdir, hdrpath)
	ret = subprocess.call([ 'cp', cppath, '.' ])
	if ret != 0:
		sys.stderr.write('error: failed to copy \'%s\'\n' % cppath)
		sys.exit(1)

	# no need to generate and copy preprocessor output
	if os.path.exists('tmp_nl80211.c'):
		return revinfo

	# clean source tree
	cmd = 'make -C %s clean' % srcdir
	ret = subprocess.call(cmd.split())
	if ret != 0:
		sys.stderr.write('error: cleaning source tree failed\n')
		sys.exit(1)

	# generate preprocessed source file
	wldir = os.path.dirname(srcpath)
	fname = os.path.basename(srcpath)
	cmd = 'make -C %s M=%s %s' % (srcdir, wldir, fname)
	ret = subprocess.call(cmd.split())
	if ret != 0:
		sys.stderr.write('error: failed to generate \'%s\'\n' % srcpath)
		sys.exit(1)

	cppath = os.path.join(srcdir, srcpath)
	ret = subprocess.call([ 'cp', cppath, '.' ])
	if ret != 0:
		sys.stderr.write('error: failed to copy \'%s\'\n' % cppath)
		sys.exit(1)

	return revinfo

def rmpfx(name, pfx='NL80211_'):
	n = name.lstrip('_')
	if not n.startswith(pfx):
		return name
	return n[len(pfx):]

def oper_str(oper):
	if isinstance(oper, c_ast.Constant):
		return str(oper.value)
	elif isinstance(oper, c_ast.ID):
		return rmpfx(oper.name)
	elif isinstance(oper, c_ast.BinaryOp):
		return binary_oper_str(oper)
	return None

def binary_oper_str(op):
	c = op.children()
	left = c[0][1]
	right = c[1][1]
	return '%s %s %s' % (oper_str(left), op.op, oper_str(right))

def dump_binary_op(out, e, op):
	c = op.children()
	left = c[0][1]
	right = c[1][1]
	out.write('%s = %s\n' % (rmpfx(e.name), binary_oper_str(op)))

def dump_enum(out, enum):
	id = 0
	list = enum.children()[0][1]
	for dummy, e in list.children():
		if len(e.children()) == 0:
			out.write('%s = %d\n' % (rmpfx(e.name), id))
			id += 1
		elif isinstance(e.children()[0][1], (c_ast.ID, c_ast.Constant)):
			out.write('%s = %s\n' % (rmpfx(e.name), oper_str(e.children()[0][1])))
		elif isinstance(e.children()[0][1], c_ast.BinaryOp):
			dump_binary_op(out, e, e.children()[0][1])
		else:
			print(e.children()[0][1])

def dump_enum2str(out, count, enum):
	list = enum.children()[0][1]
	if enum.name == None:
		out.write('unnamed%dtostr = {\n' % count)
	else:
		out.write('%s2str = {\n' % enum.name)
	for dummy, e in list.children():
		if len(e.children()) != 0:
			if not isinstance(e.children()[0][1], c_ast.BinaryOp):
				continue
			if e.children()[0][1].op != '<<':
				continue
		out.write('\t%s: "%s",\n' % (rmpfx(e.name), e.name))
	out.write('}\n')

def dump_filehdr(out, git):
	out.write('###########################################################\n')
	out.write('# This file is generated using extract.py using pycparser\n')
	out.write('###########################################################\n')
	out.write('# revision:\n')
	out.write('#\t%s' % git)
	out.write('###########################################################\n')

def generate_defs(destdir, git, ast):
	sys.stderr.write('generating python definitions\n')
	defs = open(os.path.join(destdir, 'defs.py'), 'w')
	dump_filehdr(defs, git)
	for ext in ast.ext:
		if isinstance(ext.type, c_ast.Enum):
			dump_enum(defs, ext.type)
	defs.close()

def generate_strmap(destdir, git, ast):
	sys.stderr.write('generating python string mappings\n')
	count = 0
	strmap = open(os.path.join(destdir, 'strmap.py'), 'w')
	dump_filehdr(strmap, git)
	strmap.write('from defs import *\n')
	for ext in ast.ext:
		if isinstance(ext.type, c_ast.Enum):
			dump_enum2str(strmap, count, ext.type)
			count += 1
	strmap.close()

def append_policy(out, decl):
	override = str('%s|%s.py' % ('extract.d', decl.name)).replace('|', os.sep)
	if not os.path.exists(override):
		return
	out.write('# append/override %s entries\n' % decl.name)
	poldef = open(override, 'r')
	for l in poldef:
		out.write(l)
	poldef.close()

def get_policy_entry_type(exprs):
	for initexp in exprs:
		if oper_str(initexp.name[0]) == 'type':
			return oper_str(initexp.expr)
	return 'NLA_UNSPEC'

def dump_policy_array(out, decl):
	out.write('#\n# policy: %s\n#\n' % decl.name)
	out.write('%s = nla_policy_array(' % decl.name)
	out.write('%s' % oper_str(decl.type.dim))
	out.write(')\n')
	for exp in decl.init.exprs:
		comma_prefix = False
		type = get_policy_entry_type(exp.expr.exprs)
		for initexp in exp.expr.exprs:
			# kernel policy member 'len' has different meaning
			# depending on the type. Below comment taken from
			# kernel documentation of struct nla_policy:
			#
			# Meaning of `len' field:
			#    NLA_STRING           Maximum length of string
			#    NLA_NUL_STRING       Maximum length of string (excluding NUL)
			#    NLA_FLAG             Unused
			#    NLA_BINARY           Maximum length of attribute payload
			#    NLA_NESTED           Don't use `len' field -- length verification is
			#                         done by checking len of nested header (or empty)
			#    NLA_NESTED_COMPAT    Minimum length of structure payload
			#    NLA_U8, NLA_U16,
			#    NLA_U32, NLA_U64,
			#    NLA_S8, NLA_S16,
			#    NLA_S32, NLA_S64,
			#    NLA_MSECS            Leaving the length field zero will verify the
			#                         given type fits, using it verifies minimum length
			#                         just like "All other"
			#    All other            Minimum length of attribute payload
			field = oper_str(initexp.name[0])
			if field == 'len':
				if type in [ 'NLA_STRING', 'NLA_NUL_STRING', 'NLA_BINARY' ]:
					field = 'max_len'
				elif type in [ 'NLA_FLAG', 'NLA_NESTED' ]:
					continue
				else:
					field = 'min_len'
			out.write('%s[%s].%s = ' % (decl.name, oper_str(exp.name[0]), field))
			out.write('%s\n' % oper_str(initexp.expr))

def generate_policy(destdir, git):
	# we first extract all nla_policy definitions
	# from the source file and feed only those to
	# the abstract source tree parser. Skip if the
	# temporary file exist (useful for fixing up
	# manually).
	if not os.path.exists('tmp_nl80211.c'):
		sys.stderr.write('extract policy definitions\n')
		inputdata = open('nl80211.i', 'r').read()
		policies = re.findall('(struct nla_policy[ \t\n]+.+_policy\[.+\][ \t\n]+[^;]+;)', inputdata, re.M)
		tmpfile = open('tmp_nl80211.c', 'w')
		tmpfile.write('#include "extract.h"\n')
		for p in policies:
			tmpfile.write(p+'\n')
		tmpfile.close()
	ast = parse_file('tmp_nl80211.c', use_cpp=True)
	if ast == None:
		return

	# generate policy maps
	polmap = open(os.path.join(destdir, 'policy.py'), 'w')
	dump_filehdr(polmap, git)
	sys.stderr.write('create policy mappings\n')
	n = 0
	polmap.write('from netlink.capi import *\n')
	polmap.write('from defs import *\n\n')
	polmap.write('NLA_NUL_STRING = NLA_NESTED + 2\n')
	polmap.write('NLA_BINARY = NLA_NESTED + 3\n')
	polmap.write('NLA_S8 = NLA_NESTED + 4\n')
	polmap.write('NLA_S16 = NLA_NESTED + 5\n')
	polmap.write('NLA_S32 = NLA_NESTED + 6\n')
	polmap.write('NLA_S64 = NLA_NESTED + 7\n\n')
	for ext in ast.ext:
		# filter out array declarations
		if not isinstance(ext.type, c_ast.ArrayDecl):
			continue
		# check if it is a nla_policy
		if not isinstance(ext.type.type.type, c_ast.Struct):
			continue
		if not ext.type.type.type.name == 'nla_policy':
			continue
		if not hasattr(ext, 'init'):
			# maybe need to shout here?
			continue
		dump_policy_array(polmap, ext)
		append_policy(polmap, ext)
	polmap.close()

###########################################################
# start of script
###########################################################
def run(srcdir, destdir):
	rev = extract_prepare(srcdir)

	ast = parse_file(EXTRACT_HEADER, use_cpp=True)
	generate_defs(destdir, rev, ast)
	generate_strmap(destdir, rev, ast)
	generate_policy(destdir, rev)
	sys.stderr.write('Done!\n')

if __name__ == "__main__":
	try:
		parser = argparse.ArgumentParser(description='extract code from nl80211 source files')
		parser.add_argument('srcdir', help='source tree holding nl80211 files')
		parser.add_argument('destdir', help='directory to store generated files')
		args = parser.parse_args()
		run(args.srcdir, args.destdir)
	except SystemExit:
		sys.stderr.write('Aborting..!!\n')

