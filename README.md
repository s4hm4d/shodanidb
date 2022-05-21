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
  -nmap         Run Nmap Service Detection


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


### Compare

Before using this switch, you need save the output to a JSON file first:

```shell
echo 149.202.182.140 | shodanidb -json output.json
```

Then you can get the new resutls by comparing with the JSON file:

```shell
echo 149.202.182.140 | shodanidb -compare output.json
```

It can be used with the other switches:

```shell
echo 149.202.182.140 | shodanidb -nmap -compare output.json
echo 149.202.182.140 | shodanidb -url -compare output.json
echo 149.202.182.140 | shodanidb -url -nmap -compare output.json
```


### Nmap

To run this switch you need to have nmap installed.

It uses the nmap service detection with this command for every IP address:

```shell
nmap -sV -Pn IP -p Ports
```

It can be used with the other switches:

```shell
echo 149.202.182.140 | shodanidb -nmap
echo 149.202.182.140 | shodanidb -url -nmap
echo 149.202.182.140 | shodanidb -nmap -compare output.json
```


### url

This switch show the results as the `ip:port` format.

```shell
echo 149.202.182.140 | shodanidb -url
echo 149.202.182.140 | shodanidb -url -compare output.json
```


## Credit

The original tool is [nrich](https://gitlab.com/shodan-public/nrich). I wanted to learn Go and write this tool with Go for practice.

Also the idea for `-url` switch was gotten from [sdlookup](https://github.com/j3ssie/sdlookup).