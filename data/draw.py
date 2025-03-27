#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("scan_parsed.csv")
# Convert status -> numeric
df["NumericStatus"] = df["Status"].apply(lambda s: 1 if s=="success" else 0)

plt.figure()
plt.plot(df["ReqIndex"], df["NumericStatus"], 'ro')
plt.xlabel("Connection request")
plt.ylabel("connection result")
plt.title("Per-request success/fail (1=success, 0=fail)")
plt.grid(True)
plt.show()
