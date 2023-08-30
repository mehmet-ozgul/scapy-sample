#!/usr/bin/env bash

function main() {
    source ./venv/bin/activate
    for f in ./scenarios/*.yaml; do
        echo "Generating $f"
        python ./generate_better.py -s $f
    done
}

main