#!/usr/bin/python

import argparse
import glob
import os

parser = argparse.ArgumentParser("XPS configuration settings")

parser.add_argument('--get-xps',
                    action="store_true")

parser.add_argument('--set-xps',
                    action="store_true")

parser.add_argument('--dev',
                    required=True)

args = parser.parse_args()

ncpus = 8
cpus = [0, 4, 1, 5, 2, 6, 3, 7]
masks = [ 1 << i for i in cpus ]

def get_xps():
    dir = "/sys/class/net/%s/queues/" % (args.dev)
    def get_xps_queue(dir):
        file = dir + "/xps_cpus"
        return open(file).read().strip()

    print "Device", args.dev
    for txq in glob.glob(dir + "tx-*"):
        print os.path.basename(txq), get_xps_queue(txq)


def set_xps():
    dir = "/sys/class/net/%s/queues/" % (args.dev)
    def set_xps_queue(dir,mask):
        file = dir + "/xps_cpus"
        return open(file,'w').write("%x" % mask)

    print "Device", args.dev
    for txq, mask in zip(glob.glob(dir + "tx-*"), masks):
        print os.path.basename(txq), mask
        set_xps_queue(txq, mask)

if args.get_xps:
    get_xps()
elif args.set_xps:
    set_xps()
