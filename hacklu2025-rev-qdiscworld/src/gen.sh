#!/bin/bash
function op {
    if [ "$1" = "-" ]; then
        echo 0
    else
        hex=$(grep -A16 'flags *name' qdiscworld.sh | grep -v 'flags *name' | grep -F " $1 " | sed 's/## *[0-9]* *\([0-9]*\).*/0x\1/')
        echo $((${hex}))
    fi
}
function insns {
    IFS=$'\n'
    for ops in $(grep -A1000 encoding qdiscworld.sh | sed '/I=/q' | grep '^ *##   [0-9a-f][0-9a-f]' | \
                 sed 's/^ *#/#/' | sed 's/    /\t/g' | tr -s '\t' | cut -f4 | sed 's/^ *//'); do
        IFS=' '
        uc=0
        for opn in $ops; do
            uc=$((uc | $(op $opn)))
        done
        echo $uc
    done
}
insns
