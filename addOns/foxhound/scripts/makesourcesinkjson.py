#!/usr/bin/python

import json

def addEntries(filename, a):
    with open(filename) as file:
        for line in file:
            line = line.strip()
            line = line.replace("\"", "").replace(",", "")
            if line is not "" and line[0] != "/":
                print(line)
                s = {}
                s["name"] = line
                s["tags"] = []
                a.append(s)

filename = "sources.txt"

d = {}
d["sources"] = []
d["sinks"] = []

addEntries("sources.txt", d["sources"])
addEntries("sinks.txt", d["sinks"])

with open("sourcessinks.json", "w") as file:
    json.dump(d, file, indent=4, sort_keys=True)


