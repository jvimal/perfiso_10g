#!/bin/bash

dev=eth2

tc qdisc del dev $dev root

rmmod sch_htb sch_eyeq sch_prl

function new {
    insmod ./sch_eyeq.ko
}

new

tc qdisc add dev $dev root handle 1: htb default 1
tc class add dev $dev classid 1:1 parent 1: htb rate 1Gbit
tc class add dev $dev classid 1:10 parent 1:1 htb rate 1Gbit
tc class add dev $dev classid 1:11 parent 1:1 htb rate 1Gbit
tc class add dev $dev classid 1:12 parent 1:1 htb rate 1Gbit

tc filter add dev $dev protocol ip parent 1: prio 1 u32 match \
    ip dport 5001 0xffff flowid 1:10

tc filter add dev $dev protocol ip parent 1: prio 1 u32 match \
    ip dport 5002 0xffff flowid 1:11

tc filter add dev $dev protocol ip parent 1: prio 1 u32 match \
    ip dport 5003 0xffff flowid 1:12
