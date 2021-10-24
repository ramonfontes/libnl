import subprocess
import argparse
import os.path
import sys
import extract

def pr_info(s):
	print('\033[92m'+s+'\033[0m')

def checkout_source(srcdir, src):
	if not os.path.exists('%s/.git/refs/remotes/%s' % (srcdir, src)):
		raise Exception('specified source branch not found: %s' % src)
	FETCH = 'git --work-tree=%s --git-dir=%s/.git fetch %s %s' % ((srcdir, srcdir) + tuple(src.split('/')))
	pr_info(" * refresh %s in %s" % (src, srcdir))
	ret = subprocess.call(FETCH.split())
	if ret < 0:
		raise Exception('updating source branch failed: err=%d (%s)' % (ret, src))

	CO = 'git --work-tree=%s --git-dir=%s/.git checkout %s' % (srcdir, srcdir, src)
	pr_info(" * checking out %s in %s" % (src, srcdir))
	ret = subprocess.call(CO.split())
	if ret < 0:
		raise Exception('source branch checkout failed: err=%d (%s)' % (ret, src))

def checkout_target(target):
	if not os.path.exists('../.git/refs/heads/%s' % target):
		raise Exception('specified target branch not found: %s' % target)
	CLEAN = 'git clean -f'
	subprocess.call(CLEAN.split())
	CO = 'git checkout %s' % target
	pr_info(" * checking out local %s branch" % target)
	ret = subprocess.call(CO.split())
	if ret < 0:
		raise Exception('target branch checkout failed: err=%d (%s)' % (ret, target))

def commit_target(srcdir, repo):
	gitdir = os.path.join(srcdir, '.git')
	revinfo = subprocess.check_output(['git', '--git-dir=%s' % gitdir, 'describe'])
	commit = open('/tmp/%s.commit' % repo, 'w')
	commit.write('lib: generated: update files from %s repo\n\n' % repo)
	commit.write('Generated files from %s repo using\nrevision %s\n' % (repo, revinfo))
	commit.close()
	COMMIT = 'git commit -a -s -F /tmp/%s.commit' % repo
	ret = subprocess.call(COMMIT.split())
	if ret < 0:
		raise Exception('failed to commit generated files')

try:
	cfg = None
	parser = argparse.ArgumentParser(description='update branches')
	parser.add_argument('--config', help='branch configuration file', default='update.conf')
	parser.add_argument('srcdir', help='source tree holding nl80211 files')
	args = parser.parse_args()

	cfg = open(args.config, 'r')
	for spec in cfg:
		if spec.startswith('#'):
			continue
		target, source, repo = spec.split('\n')[0].split(':')
		pr_info('generating files for %s from %s' % (target, repo))
		checkout_target(target)
		checkout_source(args.srcdir, source)
		extract.run(args.srcdir, '../lib/generated')
		commit_target(args.srcdir, repo)
except SystemExit:
	print('Aborting!\n')
	sys.exit(1)
finally:
	if cfg != None:
		cfg.close()
