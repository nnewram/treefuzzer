#!/usr/bin/sh
echo "Lé Code: "
cat tests/possible.c
sleep 5
echo "Function trace: "
python3 TreeFuzz.py tests/a.out --print
sleep 5
echo "Analazys: "
python3 TreeFuzz.py tests/a.out
