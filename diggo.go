package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"errors"
	"io"
	"regexp"
	"strings"
	"github.com/likexian/whois-go"
)

var (
	Black   = Color("\033[1;30m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Green   = Color("\033[1;32m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Purple  = Color("\033[1;34m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Teal    = Color("\033[1;36m%s\033[0m")
	White   = Color("\033[1;37m%s\033[0m")
)

// nslookup function
func nslookup(domain string) {
	fmt.Println(Green("[i] nslookup --->"))
	
	fmt.Println(Green("IP's:"))
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		//os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf(Green(domain+". IN A %s\n"), Green(ip.String()))
	}
	
	fmt.Println("")
	fmt.Println(Green("NS records: "))
	nsrecords, _ := net.LookupNS(domain)
	for _, ns := range nsrecords {
		fmt.Println(Green(ns))
	}
	
	fmt.Println("")
	fmt.Println(Green("TXT records: "))
	txtrecords, _ := net.LookupTXT(domain)

	for _, txt := range txtrecords {
		fmt.Println(Green(txt))
	}

	fmt.Println("")
	fmt.Println(Green("MX records: "))
	mxrecords, _ := net.LookupMX(domain)

	for _, mx := range mxrecords {
		fmt.Println(Green(mx))
	}
	fmt.Println("")
	

}


// whoios function
func whoisinfo(domain string, update string) {
	fmt.Println(Teal("[i] whois --->"))
	result, err := whois.Whois(domain)
	if err == nil {
	    fmt.Println(Teal(result))
	}
	re := regexp.MustCompile(`Organization.*`)
	matches := re.FindStringSubmatch(result)
	if len(matches) > 0 {
		match := strings.Split(matches[0] , ":")
		company := strings.TrimSpace(match[1])
		if len(company) > 1 {
			ripe(company, update)
		}
	}


}

// ripe function
func ripe(company string, update string) {
	if update == "yes" {
		fmt.Println(Purple("*** Updating ripe database ***"))
		downloadFile("https://ftp.ripe.net/ripe/dbase/ripe.db.gz","ripe.db.gz")
	}

	fmt.Println(Purple("[i] ripe --->"))
	cmd := exec.Command("zgrep", "-A14", "-B1", string(company), "ripe.db.gz")
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Println(fmt.Sprint(err) + ": " + string(output))
					return
				}
				fmt.Println(Purple(string(output)))

}



// subdomains bruteforce
func subdomains(dictionary string, domain string) {
	fmt.Println("")
	fmt.Println(Green(Magenta("[i] subdomains --->")))
	file, err := os.Open(dictionary)

	if err != nil {
		log.Fatalf("failed to open")

	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}

	file.Close()

	for _, each_ln := range text {
		//fmt.Println(each_ln)
		ips, err := net.LookupIP(each_ln + "." + domain)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
			//os.Exit(1)
		}
		for _, ip := range ips {
			fmt.Printf(Magenta(each_ln + "." + domain + ". IN A %s\n"), Magenta(ip.String()))
		}
	}
}

// upload ripe database
func downloadFile(URL, fileName string) error {
	//Get the response bytes from the url
	response, err := http.Get(URL)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return errors.New("Received non 200 response code")
	}
	//Create a empty file
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	//Write the bytes to the fiel
	_, err = io.Copy(file, response.Body)
	if err != nil {
		return err
	}

	return nil
}

// set console colors
func Color(colorString string) func(...interface{}) string {
  sprint := func(args ...interface{}) string {
    return fmt.Sprintf(colorString,
      fmt.Sprint(args...))
  }
  return sprint
}

func main() {

	var (
		domain *string
		dictionary *string
		update *string
	)


	domain = flag.String("domain", "google.es", "target domain")
	dictionary = flag.String("dictionary", "names.txt", "subdomain dictionary")
	update = flag.String("update", "no", "update ripe database")
	flag.Parse()



	nslookup(*domain)
	whoisinfo(*domain, *update)
	subdomains(*dictionary, *domain)
}
