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
	"sync"
	"reflect"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
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
	flag.BoolVar(&noCPEs, "nc", false, "Hide CPEs")

	var noHostnames bool
	flag.BoolVar(&noHostnames, "nh", false, "Hide hostnames")

	var noTags bool
	flag.BoolVar(&noTags, "nt", false, "Hide tags")

	var noVulns bool
	flag.BoolVar(&noVulns, "nv", false, "Hide vulnerabilities")

	var noColor bool
	flag.BoolVar(&noColor, "nocolor", false, "Disable color in output")

	var jsonFile string
	flag.StringVar(&jsonFile, "json", "", "Save output to JSON format")

	var verbose bool
	flag.BoolVar(&verbose, "v", false, "Verbose")

	var compareFile string
	flag.StringVar(&compareFile, "compare", "", "Compare data with a JSON file")

	var url bool
	flag.BoolVar(&url, "url", false, "Show URLs only")

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

	targets = loadTargets(inputs, verbose)

	channel := make(chan Response, 10)
	var wg sync.WaitGroup

	for i := 0; i < len(targets); i++ {
		wg.Add(1)

		i := i

		go func() {
			jsonData := getData(&wg, targets[i], verbose)
			channel <- jsonData
		}()
	}

	if jsonFile == "" && compareFile == "" {
		for i := 0; i < len(targets); i++ {
			printResult(<-channel, noCPEs, noHostnames, noTags, noVulns, noColor, url)
		}
	}

	go func() {
		wg.Wait()
		close(channel)
	}()

	if jsonFile != "" {
		saveJson(channel, jsonFile)
		return
	}

	if compareFile != "" {
		newData := make(map[string]Response)
		for ret := range channel {
			if ret.IP != "" {
				newData[ret.IP] = ret
			}
		}
		monitorData(newData, compareFile)

		var jsonDatas []Response
		for _, jsonData := range newData {
			if jsonData.IP != "" {
				jsonDatas = append(jsonDatas, jsonData)
			}
		}
		if len(jsonDatas) != 0 {
			stringData, _ := json.Marshal(jsonDatas)
			_ = ioutil.WriteFile(compareFile, stringData, 0644)
		}
		return
	}
}


func monitorData(newData map[string]Response, jsonFile string) {

	var jsonDatas []Response
	oldData := make(map[string]Response)

	theFile, err := os.Open(jsonFile)
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
			compareData(oData, nData)
		} else {
			newPorts := nData.Ports
			ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(newPorts)), ", "), "[]")
			fmt.Println(nData.IP)
			fmt.Println(ports)
		}
	}

	return
}


func compareData(oldData Response, newData Response) {
	if !reflect.DeepEqual(oldData.Ports, newData.Ports) {
		for _, nP := range newData.Ports {
			isNew := true
			for _, oP := range oldData.Ports {
				if nP == oP {
					isNew = false
				}
			}
			if isNew {
				fmt.Println(newData.IP)
				fmt.Println(fmt.Sprint(nP) + "\n")
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
				fmt.Println(newData.IP)
				fmt.Println(fmt.Sprint(nV) + "\n")
			}
		}
	}
	return
}


func loadTargets(inputs []string, verbose bool) []string {

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


func getData(wg *sync.WaitGroup, ip string, verbose bool) Response {

	defer wg.Done()

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


func saveJson(chData chan Response, jsonFile string) {

	var jsonDatas []Response
	for jsonData := range chData {
		if jsonData.IP != "" {
			jsonDatas = append(jsonDatas, jsonData)
		}
	}

	if len(jsonDatas) != 0 {
		stringData, _ := json.Marshal(jsonDatas)
		_ = ioutil.WriteFile(jsonFile, stringData, 0644)
	}
}


func printResult(jsonData Response, noCPEs bool, noHostnames bool, noTags bool, noVulns bool, noColor bool, url bool) {

	builder := &strings.Builder{}

	if jsonData.IP == "" {
		return
	}

	ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(jsonData.Ports)), ", "), "[]")

	if url {
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