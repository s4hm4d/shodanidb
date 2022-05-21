package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"reflect"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
	"github.com/Ullaakut/nmap/v2"
)

type Response struct {
	CPES	[]string
	Hostnames	[]string
	IP	string
	Ports	[]int32
	Tags	[]string
	Vulns	[]string
}

var (
	nmapScan	bool
	urls		bool
	noCPEs		bool
	noTags		bool
	noVulns		bool
	noColor		bool
	verbose		bool
	noHostnames	bool
	jsonFile	string
	compareFile	string
	concurrency	int
)

func main() {

	flag.BoolVar(&noCPEs, "nc", false, "Hide CPEs")
	flag.BoolVar(&noHostnames, "nh", false, "Hide hostnames")
	flag.BoolVar(&noTags, "nt", false, "Hide tags")
	flag.BoolVar(&noVulns, "nv", false, "Hide vulnerabilities")
	flag.BoolVar(&noColor, "nocolor", false, "Disable color in output")
	flag.StringVar(&jsonFile, "json", "", "Save output to JSON format")
	flag.BoolVar(&verbose, "v", false, "Verbose")
	flag.StringVar(&compareFile, "compare", "", "Compare new results with a JSON file")
	flag.BoolVar(&urls, "url", false, "Show only IP and Port")
	flag.IntVar(&concurrency, "c", 5, "Concurrency")
	flag.BoolVar(&nmapScan, "nmap", false, "Run Nmap Service Detection")
	flag.Parse()

	var inputs, targets []string

	if flag.NArg() > 0 {
		inputs = []string{flag.Arg(0)}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			inputs = append(inputs, sc.Text())
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	targets = loadTargets(inputs)

	allData := make([]Response, len(targets))
	var validData []Response

	var wg sync.WaitGroup
	var ch = make(chan int, len(targets))

	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
            for {
                a, ok := <-ch
                if !ok {
					wg.Done()
                    return
                }
                jsonData := getData(targets[a])
				allData[a] = jsonData
            }
        }()
	}

	for i := 0; i < len(targets); i++ {
        ch <- i
    }

	close(ch)
	wg.Wait()

	for i := 0; i < len(allData); i++ {
		if allData[i].IP != "" {
			validData = append(validData, allData[i])
		}
	}

	if jsonFile == "" && compareFile == "" {
		for i := 0; i < len(validData); i++ {
			printResult(validData[i])
		}
		if nmapScan {
			fmt.Println()
			for i := 0; i < len(validData); i++ {
				runNmap(validData[i].IP, validData[i].Ports)
			}
		}
	}

	if jsonFile != "" {
		saveJson(validData, jsonFile)
		if nmapScan {
			for i := 0; i < len(validData); i++ {
				runNmap(validData[i].IP, validData[i].Ports)
			}
		}
		return
	}

	if compareFile != "" {
		newData := make(map[string]Response)
		for _, ret := range validData {
			newData[ret.IP] = ret
		}
		monitorData(newData)
		saveJson(validData, compareFile)

		return
	}
}


func monitorData(newData map[string]Response) {

	var jsonDatas []Response
	oldData := make(map[string]Response)
	newIpPorts := make(map[string][]int32)

	theFile, err := os.Open(compareFile)
	if err != nil {
		fmt.Println(err)
	}
	defer theFile.Close()

	byteValue, _ := ioutil.ReadAll(theFile)
	json.Unmarshal(byteValue, &jsonDatas)

	for _, jsonData := range jsonDatas {
		oldData[jsonData.IP] = jsonData
	}

	for _, nData := range newData {
		oData, isInOld := oldData[nData.IP]
		if isInOld {
			newPorts := compareData(oData, nData)
			if len(newPorts) != 0 {
				newIpPorts[nData.IP] = newPorts
			}
		} else {
			newPorts := nData.Ports
			newIpPorts[nData.IP] = newPorts
			if urls {
				for _, port := range newPorts {
					fmt.Println(nData.IP + ":" + fmt.Sprint(port))
				}
			} else {			
				ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(newPorts)), ", "), "[]")
				fmt.Println(nData.IP)
				fmt.Println(ports + "\n")
			}
		}
	}
	if len(newIpPorts) != 0 {
		fmt.Println()
	}
	if nmapScan {
		for ip, ports := range newIpPorts {
			runNmap(ip, ports)
		}
	}
	return
}


func compareData(oldData Response, newData Response) []int32 {
	var newPorts []int32
	if !reflect.DeepEqual(oldData.Ports, newData.Ports) {
		for _, nP := range newData.Ports {
			isNew := true
			for _, oP := range oldData.Ports {
				if nP == oP {
					isNew = false
				}
			}
			if isNew {
				if urls {
					fmt.Println(newData.IP + ":" + fmt.Sprint(nP))
				} else {
					fmt.Println(newData.IP)
					fmt.Println(fmt.Sprint(nP) + "\n")
				}
				newPorts = append(newPorts, nP)
			}
		}
	}
	if !reflect.DeepEqual(oldData.Vulns, newData.Vulns) {
		for _, nV := range newData.Vulns {
			isNew := true
			for _, oV := range oldData.Vulns {
				if nV == oV {
					isNew = false
				}
			}
			if isNew {
				if urls {
					fmt.Println(newData.IP + ":" + fmt.Sprint(nV))
				} else {
					fmt.Println(newData.IP)
					fmt.Println(fmt.Sprint(nV) + "\n")
				}
			}
		}
	}
	return newPorts
}


func loadTargets(inputs []string) []string {

	var targets []string

	for _, target := range inputs {
		if iputil.IsCIDR(target) {
			cidrIps, err := mapcidr.IPAddresses(target)
			if err != nil {
				if verbose {
					log.Printf("Couldn't parse CIDR!\n")
				}
				return []string{}
			}
			for _, ip := range cidrIps {
				targets = append(targets, ip)
			}
		} else {
			targets = append(targets, target)
		}
	}

	return targets
}


func getData(ip string) Response {

	res, err := http.Get(
		fmt.Sprintf("https://internetdb.shodan.io/%s", ip),
	)

	if err != nil {
		if verbose {
			log.Printf("Couldn't connect to the server! (%s)", ip)
			log.Printf("%s\n", err)
		}		
		return Response{}
	}

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		if verbose {
			log.Printf("Couldn't read the data from %s", ip)
			log.Printf("%s\n", raw)
		}
		return Response{}
	}

	res.Body.Close()

	var jsonData Response
	err = json.Unmarshal(raw, &jsonData)

	if err != nil {
		if verbose {
			log.Printf("The data from %s is incorrect!", ip)
			log.Printf("%s\n", raw)
		}
		return Response{}
	}

	return jsonData
}


func saveJson(jsonDatas []Response, outputFile string) {

	if len(jsonDatas) != 0 {
		stringData, _ := json.Marshal(jsonDatas)
		_ = ioutil.WriteFile(outputFile, stringData, 0644)
	}
}


func printResult(jsonData Response) {

	builder := &strings.Builder{}

	if jsonData.IP == "" {
		return
	}

	ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(jsonData.Ports)), ", "), "[]")

	if urls {
		if (jsonData.Ports == nil) {
			return
		} 
		for _, port := range jsonData.Ports {
			fmt.Println(jsonData.IP + ":" + fmt.Sprint(port))
		}
		return
	}

	fmt.Println(jsonData.IP)

	if !noColor {
		builder.WriteString("Ports: " + aurora.Green(ports).String() + "\n")
	} else {
		builder.WriteString("Ports: " + ports + "\n")
	}

	if (!noCPEs && len(jsonData.CPES) > 0) {
		cpes := strings.Join(jsonData.CPES, ", ")
		if !noColor {
			builder.WriteString("CPEs: " + aurora.Yellow(cpes).String() + "\n")
		} else {
			builder.WriteString("CPEs: " + cpes + "\n")
		}
	}

	if (!noVulns && len(jsonData.Vulns) > 0) {
		vulns := strings.Join(jsonData.Vulns, ", ")
		if !noColor {
			builder.WriteString("Vulnerabilities: " + aurora.Red(vulns).String() + "\n")
		} else {
			builder.WriteString("Vulnerabilities: " + vulns + "\n")
		}
	}

	if (!noHostnames && len(jsonData.Hostnames) > 0) {
		hostnames := strings.Join(jsonData.Hostnames, ", ")
		if !noColor {
			builder.WriteString("Hostnames: " + aurora.Blue(hostnames).String() + "\n")
		} else {
			builder.WriteString("Hostnames: " + hostnames + "\n")
		}
	}

	if (!noTags && len(jsonData.Tags) > 0) {
		tags := strings.Join(jsonData.Tags, ", ")
		if !noColor {
			builder.WriteString("Tags: " + aurora.Magenta(tags).String() + "\n")
		} else {
			builder.WriteString("Tags: " + tags + "\n")
		}
	}

	fmt.Println(builder.String())
}

func runNmap(target string, intPorts []int32) {

	ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(intPorts)), ", "), "[]")

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithServiceInfo(),
		nmap.WithSkipHostDiscovery(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		if verbose {
			log.Printf("Warnings: \n %v", warnings)
		}
    }

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		for _, port := range host.Ports {
			fmt.Printf("%s:%d/%s %s %s %s %s %s\n", host.Addresses[0], port.ID, port.Protocol, port.State, port.Service.Name, port.Service.Product, port.Service.ExtraInfo, port.Service.Version)
		}
	}
}