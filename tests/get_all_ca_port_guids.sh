#!/bin/sh
ibnetdiscover \
| sed -ne 's/^\[[1-9]\](\([a-f|0-9]\+\)).*$/0x\1/p'
