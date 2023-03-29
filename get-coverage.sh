#!/bin/bash

cd gocovmerge
go mod tidy
go install
cd ..
ls
find ./ -name "*coverage.out" | xargs gocovmerge > final.out
go tool cover -func=final.out | grep total > tmp
result=`cat tmp | awk 'END {print $3}'`
result=${result%\%}
threshold=48.1
echo "Result:"
echo "$result%"
if (( $(echo "$result >= $threshold" |bc -l) )); then
    echo "It is equal or greater than threshold ($threshold%), passed!"
else
    echo "It is smaller than threshold ($threshold%) value, failed!"
    exit 1
fi