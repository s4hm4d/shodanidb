# shodanIDB

A command-line tool to fetch data (open ports, CVEs, CPEs, ...) from [Shodan internetDB API](https://internetdb.shodan.io/). Free to use and no API key required. 


## Installation

```
go install -v github.com/s4hm4d/shodanidb@latest
```


## Usage

```
echo [ip] | shodanidb [options]


Options:
  -nc           Hide CPEs
  -nh           Hide hostnames
  -nt           Hide tags
  -nv           Hide vulnerabilities
  -nocolor      Disable color in output
  -json         Save output to JSON format
  -v            Verbose mode


Examples:
  shodanidb [ip]
  echo [ip] | shodanidb -nt
  cat ips.txt | shodanidb -nh
  cat ips.txt | shodanidb -json output.json
  cat 8.8.8.0/24 | shodanidb
```


## Credit

The original tool is [nrich](https://gitlab.com/shodan-public/nrich). I wanted to learn Go and write this tool with Go for practice.
