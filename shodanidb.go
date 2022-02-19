package main

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"flag"
	"bufio"
	"os"
	"strings"
	"github.com/logrusorgru/aurora"
)

type Response struct {
	CPES	[]string
	Hostnames	[]string
	IP	string
	Ports	[]int32
	Tags	[]string
	Vulns	[]string
}

func main() {

	var noCPEs bool
	flag.BoolVar(&noCPEs, "nc", false, "hide cpes")

	var noHostnames bool
	flag.BoolVar(&noHostnames, "nh", false, "hide hostnames")

	var noTags bool
	flag.BoolVar(&noTags, "nt", false, "hide tags")

	var noVulns bool
	flag.BoolVar(&noVulns, "nv", false, "hide vulnerabilities")

	var noColor bool
	flag.BoolVar(&noColor, "nocolor", false, "disable color in output")

	flag.Parse()


	var ips []string

	if flag.NArg() > 0 {
		ips = []string{flag.Arg(0)}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			ips = append(ips, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	channel := make(chan Response)
	for _, ip := range ips {
		go getData(ip, channel)
	}

	for i:=0; i<len(ips); i++ {
		printResult(<-channel, noCPEs, noHostnames, noTags, noVulns, noColor)
	}
}


func getData(ip string, channel chan Response) {

	res, err := http.Get(
		fmt.Sprintf("https://internetdb.shodan.io/%s", ip),
	)

	if err != nil {
		return
	}

	raw, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return
	}

	res.Body.Close()

	var wrapper Response
	err = json.Unmarshal(raw, &wrapper)

	if err != nil {
		return
	}

	channel <- wrapper
}

func printResult(output Response, noCPEs bool, noHostnames bool, noTags bool, noVulns bool, noColor bool) {

	builder := &strings.Builder{}

	fmt.Println(output.IP)

	ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(output.Ports)), ", "), "[]")

	if !noColor {
		builder.WriteString("Ports: " + aurora.Green(ports).String() + "\n")
	} else {
		builder.WriteString("Ports: " + ports + "\n")
	}

	if (!noCPEs && len(output.CPES) > 0) {
		cpes := strings.Join(output.CPES, ", ")
		if !noColor {
			builder.WriteString("CPEs: " + aurora.Yellow(cpes).String() + "\n")
		} else {
			builder.WriteString("CPEs: " + cpes + "\n")
		}
	}

	if (!noVulns && len(output.Vulns) > 0) {
		vulns := strings.Join(output.Vulns, ", ")
		if !noColor {
			builder.WriteString("Vulnerabilities: " + aurora.Red(vulns).String() + "\n")
		} else {
			builder.WriteString("Vulnerabilities: " + vulns + "\n")
		}
	}

	if (!noHostnames && len(output.Hostnames) > 0) {
		hostnames := strings.Join(output.Hostnames, ", ")
		if !noColor {
			builder.WriteString("Hostnames: " + aurora.Blue(hostnames).String() + "\n")
		} else {
			builder.WriteString("Hostnames: " + hostnames + "\n")
		}
	}

	if (!noTags && len(output.Tags) > 0) {
		tags := strings.Join(output.Tags, ", ")
		if !noColor {
			builder.WriteString("Tags: " + aurora.Magenta(tags).String() + "\n")
		} else {
			builder.WriteString("Tags: " + tags + "\n")
		}
	}

	fmt.Println(builder.String())
}