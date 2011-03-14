"""
Dissent: Accountable Group Anonymity
Copyright (C) 2010 Yale University
Released under the GNU General Public License version 3:
see the file COPYING for details.

Filename: run_bulk.py
Author: Henry Corrigan-Gibbs
"""
import logging
from logging import debug, info
import bulk_node
import sys
from shutil import copyfile
import cProfile
from anon_crypto import AnonCrypto

def __main__(argv):
	min_key_len = 1024

	if(len(argv) != 14):
		raise ValueError, "Usage: %s id key_len round_id n_nodes my_ip my_port leader_ip leader_port dnstr_ip dnstr_port upstr_ip upstr_port msg_len" % (argv[0])

	logger = logging.getLogger()
	logger.setLevel(logging.DEBUG)
	debug("Starting node")

	id = int(argv[1])
	key_len = int(argv[2])
	round_id = int(argv[3])
	n_nodes = int(argv[4])
	my_addr = (argv[5], int(argv[6]))
	leader_addr = (argv[7], int(argv[8]))
	up_addr = (argv[9], int(argv[10]))
	dn_addr = (argv[11], int(argv[12]))
	msg_len = int(argv[13])

	msg_file = AnonCrypto.random_file(msg_len)

	node = bulk_node.bulk_node(id, key_len, round_id, n_nodes,
			my_addr, leader_addr, up_addr, dn_addr, msg_file)
	cProfile.runctx('mynode.run_protocol()', {'mynode': node}, {})
#node.run_protocol()
	fnames = node.output_filenames()

	for i in xrange(0, len(fnames)):
		copyfile(fnames[i], "data/node%04d-%04d.out" % (id, i))

	return

__main__(sys.argv)
