#!/bin/bash
host=vm
host=l1
dir='~/eyeq++'
dir='~/vimal/e2'
scp run.sh Makefile *.c *.h bottleneck.sh $host:$dir
