#!/bin/bash
set -euo pipefail



cd results-latest/results-intel-mad
pipenv run python3 ../../results/render.py
cp results-2500-1000-line.eps ../../../beng-project-report/figures/results-2500-1000-line-intel.eps
cp results-2500-1000.eps ../../../beng-project-report/figures/results-2500-1000-intel.eps
cd ../results-amd-ewr
pipenv run python3 ../../results/render.py
cp results-2500-1000.eps ../../../beng-project-report/figures/results-2500-1000-amd.eps
cd ../../results-local-new
pipenv run python3 ../results/render.py
cp results-2500-1000.eps ../../beng-project-report/figures/results-2500-1000-apple.eps
cd ..
pipenv run python3 table.py \
  results-latest/results-intel-mad/results-2500-1000.csv \
  results-latest/results-amd-ewr/results-2500-1000.csv \
  results-local-new/results-2500-1000.csv
