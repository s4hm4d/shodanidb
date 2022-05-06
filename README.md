# shodanIDB

A command-line tool to fetch data (open ports, CVEs, CPEs, ...) from [Shodan internetDB API](https://internetdb.shodan.io/). Free to use and no API key required. 


## Installation

```
go install -v github.com/s4hm4d/shodanidb@latest
```


## Usage

```shell
echo <ip> | shodanidb [options]


Options:
  -nc           Hide CPEs
  -nh           Hide hostnames
  -nt           Hide tags
  -nv           Hide vulnerabilities
  -nocolor      Disable color in output
  -json         Save output to JSON format
  -compare      Compare new results with a JSON file
  -url          Show only IP and Port
  -v            Verbose mode
  -c            Concurrency (default 5)


# Simple Usage:
echo 149.202.182.140 | shodanidb

# CIDR Input:
echo 149.202.182.140/24 | shodanidb

# Use Filters (Hide CPEs, Hostnames and Tags):
echo 149.202.182.140 | shodanidb -nc -nh -nt

# Show Only IP and Ports:
echo 149.202.182.140/24 | shodanidb -url

# Save Output to a JSON File:
cat ips.txt | shodanidb -json output.json

# Show New Results by Comparing With The Old JSON File:
cat ips.txt | shodanidb -compare output.json

```


## Credit

The original tool is [nrich](https://gitlab.com/shodan-public/nrich). I wanted to learn Go and write this tool with Go for practice.

Also the idea for `-url` switch was gotten from [sdlookup](https://github.com/j3ssie/sdlookup).