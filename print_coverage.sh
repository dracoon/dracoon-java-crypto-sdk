#!/bin/bash

file="$1"

if [ ! -f $file ]; then
    echo "JaCoCo coverage file was not found!"
    exit 1
fi

awk -F "," \
    '{
      instructions += $4 + $5; covered += $5
    }
    END {
      print "Code coverage:";
      print "- Instructions covered:", 100*covered/instructions "%", "(" covered, "/", instructions ")";
    }' \
    $file