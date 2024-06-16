import pandas as pd
import sys

intel, amd, apple = sys.argv[1:]
P = 0.5

df = pd.DataFrame({
  "Intel Xeon": pd.read_csv(intel).quantile(P),
  "AMD EPYC": pd.read_csv(amd).quantile(P),
   "Apple M2 Max": pd.read_csv(apple).quantile(P),
}).transpose()

print(df)

def pct_diff(a, b):
    return (a - b) / (a + b) * 2

relative = (df.transpose() / df["Native"].transpose() - 1).drop(["Native"]).transpose()
relative.index.name = "Method"
relative.transpose().to_latex("../beng-project-report/figures/results.tex", float_format=lambda x: f"{x * 100:+.1f}\\%", escape=True, bold_rows=True)
