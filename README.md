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


Examples:
  echo [ip] | shodanidb -nt
  cat ips.txt | shodanidb -nh
```


## Credit

The original tool is [nrich](https://gitlab.com/shodan-public/nrich). I wanted to learn Go and write this tool with Go for practise.
