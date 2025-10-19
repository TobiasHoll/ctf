#!/bin/bash
set -eu
echo -e '\x1b[33mPlease wait while we set up, this might take a while.\x1b[0m'
ip link add ifb0 type ifb
ip link set ifb0 up
ip link add bare0 type bareudp dstport 0xffff ethertype 0x0800
ip link set bare0 up
ip addr add 58.51.58.51/32 dev bare0
tc qdisc add dev eth0 clsact
tc qdisc add dev lo clsact
tc qdisc add dev ifb0 root handle 1: htb default 0
tc filter add dev eth0 ingress prio 1 protocol ip basic match 'meta(pkt_len gt 1000)' action drop
tc filter add dev eth0 ingress prio 2 protocol ip u32 match mark 0 0xffffffff match ip protocol 17 ff match u8 5 0f at 0 match u16 0 3fff at 6 match u16 14899 ffff at 22 action pedit ex munge offset 28 u32 set 0 pipe action pedit ex munge offset 32 u32 set 0 pipe action pedit ex munge offset 36 u32 set 0 pipe action pedit ex munge offset 40 u32 set 0 pipe action pedit ex munge offset 44 u32 set 0 pipe action pedit ex munge offset 48 u32 set 0 pipe action pedit ex munge offset 52 u32 set 0 pipe action pedit ex munge offset 56 u32 set 0 pipe action pedit ex munge offset 60 u32 set 0 pipe action pedit ex munge offset 64 u32 set 0 pipe action pedit ex munge offset 68 u32 set 0 pipe action pedit ex munge offset 72 u32 set 0 pipe action pedit ex munge offset 76 u32 set 0 pipe action pedit ex munge offset 80 u32 set 0 pipe action pedit ex munge offset 84 u32 set 0 pipe action pedit ex munge offset 88 u32 set 0 pipe action pedit ex munge offset 92 u32 set 0 pipe action pedit ex munge offset 96 u32 set 0 pipe action pedit ex munge offset 100 u32 set 0 pipe action pedit ex munge offset 104 u32 set 0 pipe action pedit ex munge offset 108 u32 set 0 pipe action pedit ex munge offset 112 u32 set 0 continue
tc filter add dev eth0 ingress prio 3 protocol ip u32 match mark 0 0xffffffff match ip protocol 17 ff match u8 5 0f at 0 match u16 0 3fff at 6 match u16 14899 ffff at 22 action pedit ex munge offset 116 u32 set 0 pipe action pedit ex munge offset 120 u32 set 0 pipe action pedit ex munge offset 124 u32 set 0 pipe action pedit ex munge offset 128 u32 set 0 pipe action pedit ex munge offset 132 u32 set 0 pipe action pedit ex munge offset 136 u32 set 0 pipe action pedit ex munge offset 140 u32 set 0 pipe action pedit ex munge offset 144 u32 set 0 pipe action pedit ex munge offset 148 u32 set 0 pipe action pedit ex munge offset 152 u32 set 0 pipe action pedit ex munge offset 156 u32 set 0 pipe action pedit ex munge offset 160 u32 set 0 pipe action pedit ex munge offset 164 u32 set 0 pipe action pedit ex munge offset 168 u32 set 0 pipe action pedit ex munge offset 172 u32 set 0 pipe action pedit ex munge offset 176 u32 set 0 pipe action pedit ex munge offset 180 u32 set 0 pipe action pedit ex munge offset 184 u32 set 0 pipe action pedit ex munge offset 188 u32 set 0 pipe action pedit ex munge offset 192 u32 set 0 pipe action pedit ex munge offset 196 u32 set 0 pipe action pedit ex munge offset 200 u32 set 0 continue
tc filter add dev eth0 ingress prio 4 protocol ip u32 match mark 0 0xffffffff match ip protocol 17 ff match u8 5 0f at 0 match u16 0 3fff at 6 match u16 14899 ffff at 22 action pedit ex munge offset 204 u32 set 0 pipe action pedit ex munge offset 208 u32 set 0 pipe action pedit ex munge offset 212 u32 set 0 pipe action pedit ex munge offset 216 u32 set 0 pipe action pedit ex munge offset 220 u32 set 0 pipe action pedit ex munge offset 224 u32 set 0 pipe action pedit ex munge offset 228 u32 set 0 pipe action pedit ex munge offset 232 u32 set 0 pipe action pedit ex munge offset 236 u32 set 0 pipe action pedit ex munge offset 240 u32 set 0 pipe action pedit ex munge offset 244 u32 set 0 pipe action pedit ex munge offset 248 u32 set 0 pipe action pedit ex munge offset 252 u32 set 0 pipe action pedit ex munge offset 256 u32 set 0 pipe action pedit ex munge offset 260 u32 set 0 pipe action pedit ex munge offset 264 u32 set 0 pipe action pedit ex munge offset 268 u32 set 0 pipe action pedit ex munge offset 272 u32 set 0 pipe action pedit ex munge offset 276 u32 set 0 pipe action pedit ex munge offset 280 u32 set 0 pipe action pedit ex munge offset 284 u32 set 0 pipe action pedit ex munge offset 288 u32 set 0 pipe action skbedit mark 0x3a33 pipe action mirred egress redirect dev ifb0
tc filter add dev eth0 ingress prio 5 protocol ip matchall action drop
H=($(seq 0 255 | xargs -l printf '%x '))
S=($(seq 0 44 2000))
for Q in $(seq 0 $((${#S[@]} - 1))); do
    R=($(seq ${S[$Q]} $((${S[$Q]} + 44)) | xargs -l printf '%x '))
    echo -e '\x1b[2mSetup is '$((Q*100/${#S[@]}))'% done\x1b[0m'
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[1]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[2]}: u32 divisor 256
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[1]}::1 u32 ht ${R[1]}: link ${R[2]}: match mark 0 0 hashkey mask 0xff000000 at 0
    tc filter add dev ifb0 parent 1: prio 0x${R[1]} protocol ip u32 link ${R[1]}: match mark 0x3a33 0xffffffff match u16 0 ffff at 30 offset at 28 mask ffff plus 292 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[3]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[3]}::1 u32 ht ${R[3]}: match u16 0xffff ffff at 2 action drop
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[4]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[4]}::1 u32 ht ${R[4]}: match u16 0x8000 8000 at 2 action pedit ex munge ip ihl add 2 pipe action pedit ex munge offset 20 u32 set 0 pipe action pedit ex munge offset 24 u32 set 0 pipe action pedit ex munge offset 28 u32 set 0x3a33ffff pipe action pedit ex munge offset 32 u32 set 0x01240000 pipe action csum udp and ip pipe action mirred ingress redirect dev bare0 pass
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[7]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[7]}:${H[$V]}:1 u32 ht ${R[7]}:${H[$V]} match mark 0 0 action pedit ex munge offset 32 u32 set $((V << 16)) retain 0x00ff0000 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[6]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[6]}::1 u32 ht ${R[6]}: match mark 0 0 link ${R[7]}: hashkey mask 0x00ff0000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[5]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[5]}::1 u32 ht ${R[5]}: match u16 0x4000 4000 at 2 link ${R[6]}: offset at 0 mask ffff plus 264 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[10]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[10]}:${H[$V]}:1 u32 ht ${R[10]}:${H[$V]} match mark 0 0 action pedit ex munge offset 32 u32 set $((V << 24)) retain 0xff000000 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[9]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[9]}::1 u32 ht ${R[9]}: match mark 0 0 link ${R[10]}: hashkey mask 0x0000ff00 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[8]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[8]}::1 u32 ht ${R[8]}: match u16 0x2000 2000 at 2 link ${R[9]}: offset at 0 mask ffff plus 264 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[12]}: u32 divisor 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[12]}:0:1 u32 ht ${R[12]}:0 match mark 0 0 link ${R[7]}: hashkey mask 0xff000000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[12]}:1:1 u32 ht ${R[12]}:1 match mark 0 0 link ${R[7]}: hashkey mask 0x00ff0000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[12]}:2:1 u32 ht ${R[12]}:2 match mark 0 0 link ${R[7]}: hashkey mask 0x0000ff00 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[12]}:3:1 u32 ht ${R[12]}:3 match mark 0 0 link ${R[7]}: hashkey mask 0x000000ff at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[11]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[11]}::1 u32 ht ${R[11]}: match u16 0x1000 1000 at 2 link ${R[12]}: hashkey mask 0x00030000 at 4 offset at 4 mask 00fc plus 8 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[14]}: u32 divisor 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[14]}:0:1 u32 ht ${R[14]}:0 match mark 0 0 link ${R[10]}: hashkey mask 0xff000000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[14]}:1:1 u32 ht ${R[14]}:1 match mark 0 0 link ${R[10]}: hashkey mask 0x00ff0000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[14]}:2:1 u32 ht ${R[14]}:2 match mark 0 0 link ${R[10]}: hashkey mask 0x0000ff00 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[14]}:3:1 u32 ht ${R[14]}:3 match mark 0 0 link ${R[10]}: hashkey mask 0x000000ff at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[13]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[13]}::1 u32 ht ${R[13]}: match u16 0x0800 0800 at 2 link ${R[14]}: hashkey mask 0x03000000 at 4 offset at 4 mask fc00 shift 8 plus 8 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[17]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[17]}:${H[$V]}:1 u32 ht ${R[17]}:${H[$V]} match mark 0 0 action pedit ex munge offset 32 u32 set $((V << 8)) retain 0x0000ff00 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[16]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[16]}::1 u32 ht ${R[16]}: match mark 0 0 link ${R[17]}: hashkey mask 0x000000ff at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[15]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[15]}::1 u32 ht ${R[15]}: match u16 0x0400 0400 at 2 link ${R[16]}: offset at 0 mask ffff plus 264 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[19]}: u32 divisor 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[19]}:0:1 u32 ht ${R[19]}:0 match mark 0 0 link ${R[17]}: hashkey mask 0xff000000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[19]}:1:1 u32 ht ${R[19]}:1 match mark 0 0 link ${R[17]}: hashkey mask 0x00ff0000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[19]}:2:1 u32 ht ${R[19]}:2 match mark 0 0 link ${R[17]}: hashkey mask 0x0000ff00 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[19]}:3:1 u32 ht ${R[19]}:3 match mark 0 0 link ${R[17]}: hashkey mask 0x000000ff at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[18]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[18]}::1 u32 ht ${R[18]}: match u16 0x0200 0200 at 2 link ${R[19]}: hashkey mask 0x00030000 at 4 offset at 4 mask 00fc plus 8 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[20]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[20]}::1 u32 ht ${R[20]}: match u16 0x0100 0100 at 2 link ${R[19]}: hashkey mask 0x03000000 at 4 offset at 4 mask fc00 shift 8 plus 8 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[21]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[21]}::1 u32 ht ${R[21]}: match u16 0x0080 0080 at 2 action pedit ex munge offset 34 u8 invert continue
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[22]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[22]}::1 u32 ht ${R[22]}: match u16 0x0040 0040 at 2 action pedit ex munge offset 32 u32 add 0x100 retain 0x0000ff00 continue
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[25]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[25]}:${H[$V]}:1 u32 ht ${R[25]}:${H[$V]} match mark 0 0 action pedit ex munge offset 32 u32 add $((V << 8)) retain 0x0000ff00 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[24]}: u32 divisor 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[24]}:0:1 u32 ht ${R[24]}:0 match mark 0 0 link ${R[25]}: hashkey mask 0xff000000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[24]}:1:1 u32 ht ${R[24]}:1 match mark 0 0 link ${R[25]}: hashkey mask 0x00ff0000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[24]}:2:1 u32 ht ${R[24]}:2 match mark 0 0 link ${R[25]}: hashkey mask 0x0000ff00 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[24]}:3:1 u32 ht ${R[24]}:3 match mark 0 0 link ${R[25]}: hashkey mask 0x000000ff at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[23]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[23]}::1 u32 ht ${R[23]}: match u16 0x0020 0020 at 2 link ${R[24]}: hashkey mask 0x00030000 at 4 offset at 4 mask 00fc plus 8 eat
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[28]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[28]}:${H[$V]}:1 u32 ht ${R[28]}:${H[$V]} match mark 0 0 action pedit ex munge offset 36 u32 at 33 fc 0 set $((V << 24)) retain 0xff000000 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[29]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[29]}:${H[$V]}:1 u32 ht ${R[29]}:${H[$V]} match mark 0 0 action pedit ex munge offset 36 u32 at 33 fc 0 set $((V << 16)) retain 0x00ff0000 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[30]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[30]}:${H[$V]}:1 u32 ht ${R[30]}:${H[$V]} match mark 0 0 action pedit ex munge offset 36 u32 at 33 fc 0 set $((V << 8)) retain 0x0000ff00 continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[31]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[31]}:${H[$V]}:1 u32 ht ${R[31]}:${H[$V]} match mark 0 0 action pedit ex munge offset 36 u32 at 33 fc 0 set $V retain 0x000000ff continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[27]}: u32 divisor 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[27]}:0:1 u32 ht ${R[27]}:0 match mark 0 0 link ${R[28]}: hashkey mask 0x0000ff00 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[27]}:1:1 u32 ht ${R[27]}:1 match mark 0 0 link ${R[29]}: hashkey mask 0x0000ff00 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[27]}:2:1 u32 ht ${R[27]}:2 match mark 0 0 link ${R[30]}: hashkey mask 0x0000ff00 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[27]}:3:1 u32 ht ${R[27]}:3 match mark 0 0 link ${R[31]}: hashkey mask 0x0000ff00 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[26]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[26]}::1 u32 ht ${R[26]}: match u16 0x0010 0010 at 2 link ${R[27]}: hashkey mask 0x00030000 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[33]}: u32 divisor 256
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[33]}:0:1 u32 ht ${R[33]}:0 match mark 0 0 action pedit ex munge offset 32 u32 set 1 retain 0x000000ff continue
    for V in $(seq 1 127); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[33]}:${H[$V]}:1 u32 ht ${R[33]}:${H[$V]} match mark 0 0 action pedit ex munge offset 32 u32 set 0 retain 0x000000ff continue; done
    for V in $(seq 128 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[33]}:${H[$V]}:1 u32 ht ${R[33]}:${H[$V]} match mark 0 0 action pedit ex munge offset 32 u32 set 2 retain 0x000000ff continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[32]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[32]}::1 u32 ht ${R[32]}: match u16 0x0008 0008 at 2 link ${R[33]}: hashkey mask 0x0000ff00 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[34]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[34]}::1 u32 ht ${R[34]}: match u16 0x0004 0004 at 2 match u8 0 02 at 7 action pedit ex munge offset 28 u32 set 0 retain 0x00000001 continue
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[35]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[35]}::1 u32 ht ${R[35]}: match u16 0x0002 0002 at 2 match u8 0 01 at 7 action pedit ex munge offset 28 u32 set 0 retain 0x00000001 continue
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[36]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[36]}:${H[$V]}:1 u32 ht ${R[36]}:${H[$V]} match mark 0 0 action pedit ex munge offset 28 u16 set $((((V << 2) & 255) << 8 | (V >> 6))) continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[37]}: u32 divisor 256
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[37]}:${H[$V]}:1 u32 ht ${R[37]}:${H[$V]} match mark 0 0 action pedit ex munge offset 28 u16 set $((((V & 3) << 8) | (V & 252))) pipe action pedit ex munge offset 28 u32 set 0 retain 0x0000ffff $([ $Q -ge $((${#S[@]} - 1)) ] && echo "reclassify" || echo "continue"); done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[38]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[38]}::1 u32 ht ${R[38]}: match mark 0 0 link ${R[36]}: hashkey mask 0x03fc0000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[39]}: u32 divisor 256
    for V in $(seq 0 4 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[39]}:${H[$V]}:1 u32 ht ${R[39]}:${H[$V]} match mark 0 0 action pedit ex munge offset 28 u16 add $((V << 8)) continue; done
    for V in $(seq 1 4 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[39]}:${H[$V]}:1 u32 ht ${R[39]}:${H[$V]} match mark 0 0 action pedit ex munge offset 28 u16 add $((((253 - V) << 8) + 255)) continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[40]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[40]}::1 u32 ht ${R[40]}: match u16 0x0001 0001 at 2 link ${R[39]}: hashkey mask 0x0000fd00 at 4
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[41]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[41]}::1 u32 ht ${R[41]}: match mark 0 0 action pedit ex munge offset 28 u16 add 0x0400 continue
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[42]}: u32 divisor 4
    for V in $(seq 0 3); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[42]}:${H[$V]}:1 u32 ht ${R[42]}:${H[$V]} match mark 0 0 action pedit ex munge offset 28 u16 add $((V << 8)) continue; done
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[43]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[43]}::1 u32 ht ${R[43]}: match mark 0 0 link ${R[42]}: hashkey mask 0x00030000 at 0
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[44]}: u32 divisor 1
    tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[44]}::1 u32 ht ${R[44]}: match mark 0 0 link ${R[37]}: hashkey mask 0xff000000 at 0
    for V in 3 4 5 8 11 13 15 18 20 21 22 23 26 32 34 35 38 40 41 43 44; do tc filter add dev ifb0 parent 1: prio 0x${R[V]} protocol ip u32 match mark 0x3a33 0xffffffff offset plus 28 eat link ${R[V]}:; done
    I=(128 24848 17424 24880 17456 25072 17648 25064 17640 17040 16976 17104 1025 1027 1029 8449 8451 8453 32768 26896 28944 30992)
    for V in $(seq 0 255); do tc filter add dev ifb0 parent 1: prio 0xfffd protocol ip handle ${R[2]}:${H[$V]}:1 u32 ht ${R[2]}:${H[$V]} match mark 0 0 action pedit ex munge offset 28 u32 set ${I[$V]:=65535} retain 0x0000ffff continue; done
done
tc filter add dev ifb0 parent 1: prio 0xfffe protocol ip handle 0::fe u32 match mark 0 0xffffffff match ip protocol 17 ff match u16 65535 ffff at 22 action drop
tc filter add dev ifb0 parent 1: prio 0xffff protocol ip handle 0::ff matchall action drop
echo -e '\x1b[32mService is ready.\x1b[0m'
exec su -s /usr/bin/python3 - user /server.py
