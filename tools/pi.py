#!/usr/bin/python

import argparse
import perfiso

parser = argparse.ArgumentParser(description="Perfiso Userspace Control")
parser.add_argument("--get",
                    dest="get",
                    action="store_true",
                    help="Get all parameters",
                    default=None)

parser.add_argument("--set",
                    dest="set",
                    action="store",
                    help="Set parameter number/name",
                    default=None)

parser.add_argument("--value", "-v",
                    dest="value",
                    action="store",
                    help="Value to set the parameter",
                    default=None)

parser.add_argument("--save", "-s",
                    dest="save",
                    action="store",
                    help="Save current configuration (txc, vqs, parameters)",
                    default=None)

parser.add_argument("--load", "-l",
                    dest="load",
                    action="store",
                    help="Load configuration from file.  Module will be reset.",
                    default=None)

parser.add_argument("--module", "-m",
                    dest="module",
                    action="store",
                    help="Path to perfiso module.",
                    default="./perfiso.ko iso_param_dev=eth2")

args = parser.parse_args()

if args.get:
    perfiso.get(args)
elif args.set:
    perfiso.set(args)
elif args.save:
    perfiso.save(args)
elif args.load:
    perfiso.clear()
    perfiso.load_module(args)
    perfiso.load_config(args)
else:
    parser.print_help()