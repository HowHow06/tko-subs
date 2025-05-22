package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2"

	heroku "github.com/bgentry/heroku-go"
	"github.com/gocarina/gocsv"
	"github.com/google/go-github/github"
	"github.com/miekg/dns"
	"github.com/olekukonko/tablewriter"
)

type CMS struct {
	Name     string `csv:"name"`
	Content  string `csv:"content"`
	String   string `csv:"string"`
	OverHTTP string `csv:"http"`
}

type DomainScan struct {
	Domain      string `csv:"domain"`
	Content     string `csv:"content"`
	Provider    string `csv:"provider"`
	IsInactive  bool   `csv:"is_inactive"`
	IsTakenOver bool   `csv:"is_taken_over"`
	Response    string `csv:"response"`
}

type UnprocessedDomain struct {
	Domain string `csv:"domain"`
	Reason string `csv:"reason"`
}

type Configuration struct {
	domainsFilePath     *string
	recordsFilePath     *string
	outputFilePath      *string
	unprocessedFilePath *string
	takeOver            *bool
	githubtoken         *string
	herokuusername      *string
	herokuapikey        *string
	herokuappname       *string
	threadCount         *int
	dnsServer           *string
	dnsPort             *string
	ignoreNsError       *bool
}

type DomainInput struct {
	Domain  string `csv:"domain"`
	Content string `csv:"content"`
}

var dnsServer = "8.8.8.8"
var dnsPort = "53"

func main() {
	config := Configuration{
		domainsFilePath:     flag.String("domains", "domains.csv", "CSV file containing list of domains and their contents"),
		recordsFilePath:     flag.String("data", "providers-data.csv", "CSV file containing CMS providers' string for identification"),
		outputFilePath:      flag.String("output", "output.csv", "Output file to save the results"),
		unprocessedFilePath: flag.String("unprocessed", "unprocessed_domains.csv", "Output file to save the unprocessed domains"),
		takeOver:            flag.Bool("takeover", false, "Flag to denote if a vulnerable domain needs to be taken over or not"),
		githubtoken:         flag.String("githubtoken", "", "Github personal access token"),
		herokuusername:      flag.String("herokuusername", "", "Heroku username"),
		herokuapikey:        flag.String("herokuapikey", "", "Heroku API key"),
		herokuappname:       flag.String("herokuappname", "", "Heroku app name"),
		dnsServer:           flag.String("server", "8.8.8.8", "A DNS server to direct queries to"),
		dnsPort:             flag.String("port", "53", "The DNS server port (you shouldn't have to change this)"),
		threadCount:         flag.Int("threads", 5, "Number of threads to run parallel"),
		ignoreNsError:       flag.Bool("ignoreNsError", true, "Flag to denote if to ignore NS check errors or not."),
	}
	flag.Parse()
	dnsServer = *config.dnsServer
	dnsPort = *config.dnsPort

	cmsRecords := loadProviders(*config.recordsFilePath)
	var allResults []DomainScan
	var unprocessedDomains []UnprocessedDomain

	domainsFile, err := os.Open(*config.domainsFilePath)
	showUsageOnError(err)
	defer domainsFile.Close()

	var domains []DomainInput
	if err := gocsv.UnmarshalFile(domainsFile, &domains); err != nil {
		showUsageOnError(err)
	}

	totalDomainsCount := len(domains)
	processedDomains := 0

	// Create an exec-queue with fixed size for parallel threads
	semaphore := make(chan bool, *config.threadCount)
	var wg sync.WaitGroup
	var mu sync.Mutex // For safe increment of processedDomains

	for _, domainInput := range domains {
		wg.Add(1)
		semaphore <- true
		go func(domainInput DomainInput) {
			defer wg.Done()
			scanResults, err := scanDomain(domainInput, cmsRecords, config)

			mu.Lock()
			if err == nil {
				allResults = append(allResults, scanResults...)
			} else {
				unprocessedDomains = append(unprocessedDomains, UnprocessedDomain{
					Domain: domainInput.Domain,
					Reason: err.Error(),
				})
				fmt.Printf("[%s] Domain problem : %s\n", domainInput.Domain, err)
			}

			processedDomains++
			progress := float64(processedDomains) / float64(totalDomainsCount) * 100
			fmt.Printf("%d/%d (%.2f%%)\n", processedDomains, totalDomainsCount, progress)
			mu.Unlock()

			<-semaphore
		}(domainInput)
	}
	wg.Wait()

	allResults = filterUniqueByProviderAndDomain(allResults)
	printResults(allResults)

	if *config.outputFilePath != "" {
		writeResultsToCsv(allResults, *config.outputFilePath)
		Info("Results saved to: " + *config.outputFilePath)
	}

	if *config.unprocessedFilePath != "" && len(unprocessedDomains) > 0 {
		writeUnprocessedDomainsToCsv(unprocessedDomains, *config.unprocessedFilePath)
		Info("Unprocessed domains saved to: " + *config.unprocessedFilePath)
	}
}

func filterUniqueByProviderAndDomain(scans []DomainScan) []DomainScan {
	// Map to track the presence of provider and domain combinations
	seen := make(map[string]bool)
	uniqueScans := []DomainScan{}

	for _, scan := range scans {
		// Create a unique key by combining Provider and Domain
		key := scan.Provider + "_" + scan.Domain

		// If the combination of provider and domain has not been seen, add it to the result slice
		if !seen[key] {
			uniqueScans = append(uniqueScans, scan)
			seen[key] = true
		}
	}

	return uniqueScans
}

// writeUnprocessedDomainsToCsv writes domains that couldn't be processed to a CSV file
func writeUnprocessedDomainsToCsv(unprocessedDomains []UnprocessedDomain, outputFilePath string) {
	outputFile, err := os.Create(outputFilePath)
	panicOnError(err)
	defer outputFile.Close()

	err = gocsv.MarshalFile(&unprocessedDomains, outputFile)
	panicOnError(err)
}

// panicOnError function as a generic check for error function
func panicOnError(e error) {
	if e != nil {
		panic(e)
	}
}

// showUsageOnError function as a generic check for error when panic is too aggressive
func showUsageOnError(e error) {
	if e != nil {
		fmt.Printf("Error: %s\n", e)
		flag.Usage()
		os.Exit(1)
	}
}

// Info function to print pretty output
func Info(format string, args ...interface{}) {
	fmt.Printf("\x1b[34;1m%s\x1b[0m\n", fmt.Sprintf(format, args...))
}

// unFqdn removes the trailing from a FQDN
func unFqdn(domain string) string {
	return strings.TrimSuffix(domain, ".")
}

// takeOverSub function to decide what to do depending upon the CMS
func takeOverSub(domain string, provider string, config Configuration) (bool, error) {
	switch provider {
	case "github":
		return githubCreate(domain, config)
	case "heroku":
		return herokuCreate(domain, config)
	}
	return false, nil
}

// githubCreate function to take over dangling Github Pages
// Connecting to your Github account using the Personal Access Token
func githubCreate(domain string, config Configuration) (bool, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *config.githubtoken})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	repo := &github.Repository{
		Name:            github.String(domain),
		Description:     github.String("testing subdomain takeovers"),
		Private:         github.Bool(false),
		LicenseTemplate: github.String("mit"),
	}

	// Creating a repo
	repocreate, _, err := client.Repositories.Create(ctx, "", repo)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	reponame := *repocreate.Name
	ownername := *repocreate.Owner.Login
	refURL := *repocreate.URL
	ref := "refs/heads/master"

	// Retrieving the SHA value of the head branch
	SHAvalue, _, err := client.Repositories.GetCommitSHA1(ctx, ownername, reponame, ref, "")
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	opt := &github.Reference{
		Ref: github.String("refs/heads/gh-pages"),
		URL: github.String(refURL + "/git/refs/heads/gh-pages"),
		Object: &github.GitObject{
			SHA: github.String(SHAvalue),
		},
	}

	// Creating the gh-pages branch using the SHA value obtained above
	_, _, err = client.Git.CreateRef(ctx, ownername, reponame, opt)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	Indexpath := "index.html"
	CNAMEpath := "CNAME"
	data := "This domain is temporarily suspended"

	indexfile := &github.RepositoryContentFileOptions{
		Message: github.String("Adding the index.html page"),
		Content: []byte(data),
		Branch:  github.String("gh-pages"),
	}

	// Creating the index file with the text you want to see when the domain is taken over
	_, _, err = client.Repositories.CreateFile(ctx, ownername, reponame, Indexpath, indexfile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	cnamefile := &github.RepositoryContentFileOptions{
		Message: github.String("Adding the subdomain to takeover to the CNAME file"),
		Content: []byte(domain),
		Branch:  github.String("gh-pages"),
	}

	// Creating the CNAME file with the domain that needs to be taken over
	_, _, err = client.Repositories.CreateFile(ctx, ownername, reponame, CNAMEpath, cnamefile)
	if _, ok := err.(*github.RateLimitError); ok {
		log.Println("hit rate limit")
		return false, err
	}

	Info("Please check " + domain + " after a few minutes to ensure that it has been taken over..")
	return true, nil
}

// herokuCreate function to take over dangling Heroku apps
// Connecting to your Heroku account using the username and the API key provided as flags
// Adding the dangling domain as a custom domain for your appname that is retrieved from the flag
// This results in the dangling domain pointing to your Heroku appname
func herokuCreate(domain string, config Configuration) (bool, error) {
	client := heroku.Client{Username: *config.herokuusername, Password: *config.herokuapikey}
	client.DomainCreate(*config.herokuappname, domain)
	Info("Please check " + domain + " after a few minutes to ensure that it has been taken over..")

	return true, nil
}

// scanDomain function to scan for each domain being read from the domains file
func scanDomain(domain DomainInput, cmsRecords []*CMS, config Configuration) ([]DomainScan, error) {
	// Check if the domain has a nameserver that returns servfail/refused
	if misbehavingNs, err := authorityReturnRefusedOrServfail(domain.Domain); misbehavingNs {
		scanResult := DomainScan{Domain: domain.Domain, IsInactive: true, IsTakenOver: false, Response: "REFUSED/SERVFAIL DNS status against its NS server"}
		return []DomainScan{scanResult}, nil
	} else if err != nil && !(*config.ignoreNsError) {
		return nil, fmt.Errorf("nameserver check error: %v", err)
	}

	var content string
	var err error

	// Check if CONTENT is provided in the domain
	if domain.Content != "" {
		content = domain.Content
	} else {
		// If content is not provided, call the getCnameForDomain function
		content, err = getCnameForDomain(domain.Domain)
		if err != nil {
			return nil, fmt.Errorf("CNAME lookup error: %v", err)
		}
	}

	// Check if the DNS name has a dead Apex DNS record
	exists, status, err := apexResolves(domain.Domain)
	if !exists && err == nil {
		response := "Dead Apex DNS record"
		if status != "" {
			response += ". Status " + status
		}
		scanResult := DomainScan{Domain: domain.Domain, Content: content, IsInactive: true, IsTakenOver: false, Response: response}
		return []DomainScan{scanResult}, nil
	} else if err != nil {
		return nil, fmt.Errorf("apex DNS lookup error: %v", err)
	}

	// Check if it is pointing to a CONTENT that doesn't exist
	// exists, status, err = resolves(unFqdn(content))
	exists, status, err = resolves(unFqdn(domain.Domain))
	if err != nil {
		scanResult := DomainScan{Domain: domain.Domain, Content: content, IsInactive: true, IsTakenOver: false, Response: "Error when resolving DNS Content, require manual check"}
		return []DomainScan{scanResult}, nil
	} else if !exists {
		response := "Potential Dead DNS record"
		if status != "" {
			response += ". Status " + status
		}
		scanResult := DomainScan{Domain: domain.Domain, Content: content, IsInactive: true, IsTakenOver: false, Response: response}
		return []DomainScan{scanResult}, nil
	}

	scanResults := checkContentAgainstProviders(domain.Domain, content, cmsRecords, config)
	if len(scanResults) == 0 {
		// No provider match found for this content
		return nil, fmt.Errorf("content [%s] found but could not determine provider", content)
	}
	return scanResults, nil
}

// apexResolves function returns false if the domain's apex returns NXDOMAIN OR SERVFAIL OR REFUSED, and true otherwise
// Now also returns the specific status message when apexResolves is false
func apexResolves(domain string) (bool, string, error) {
	apex, err := publicsuffix.EffectiveTLDPlusOne(unFqdn(domain))
	exists, status, err := resolves(apex)
	if err != nil {
		return false, "", err
	}
	return exists, status, nil
}

// resolves function returns false if NXDOMAIN OR SERVFAIL OR REFUSED, and true otherwise
func resolves(domain string) (bool, string, error) {
	client := dns.Client{}
	message := dns.Msg{}

	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := client.Exchange(&message, dnsServer+":"+dnsPort)
	if err != nil {
		return false, "", err
	}

	var status string
	switch r.Rcode {
	case dns.RcodeNameError:
		status = "NXDOMAIN"
	case dns.RcodeServerFailure:
		status = "SERVFAIL"
	case dns.RcodeRefused:
		status = "REFUSED"
	}

	if r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
		return false, status, nil
	}
	return true, "", nil
}

// getCnameForDomain function to lookup the last CNAME record of a domain
//
// For example, if you have a DNS chain that looks like this:
// foo.example.com -> bar.example.com -> baz.example.com -> 1.2.3.4
// getCnameForDomain will return baz.example.com
// Doing CNAME lookups using GOLANG's net package or for that matter just doing a host on a domain
// does not necessarily let us know about any dead DNS records. So, we need to read the raw DNS response
// to properly figure out if there are any dead DNS records
func getCnameForDomain(domain string) (string, error) {
	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	r, _, err := c.Exchange(&m, dnsServer+":"+dnsPort)
	if err != nil {
		return "", err
	} else if len(r.Answer) == 0 {
		return "", errors.New("Cname not found")
	}

	record := r.Answer[len(r.Answer)-1].(*dns.CNAME)
	lastCname := record.Target

	for ok := true; ok; ok = len(r.Answer) > 0 {
		record = r.Answer[len(r.Answer)-1].(*dns.CNAME)
		lastCname = record.Target

		m.SetQuestion(dns.Fqdn(lastCname), dns.TypeCNAME)
		r, _, err = c.Exchange(&m, dnsServer+":"+dnsPort)
		if err != nil {
			break
		}
	}

	return lastCname, nil
}

// function parseNS to parse NS records (found in answer to NS query or in the authority section) into a list of record values
func parseNS(records []dns.RR) []string {
	var recordData []string
	for _, ans := range records {
		if ans.Header().Rrtype == dns.TypeNS {
			record := ans.(*dns.NS)
			recordData = append(recordData, record.Ns)
		} else if ans.Header().Rrtype == dns.TypeSOA {
			record := ans.(*dns.SOA)
			recordData = append(recordData, record.Ns)
		}
	}
	return recordData
}

// getAuthorityForDomain function to lookup the authoritative nameservers of a domain
func getAuthorityForDomain(domain string, nameserver string) ([]string, error) {
	c := dns.Client{}
	m := dns.Msg{}

	domain = dns.Fqdn(domain)

	m.SetQuestion(domain, dns.TypeNS)
	r, _, err := c.Exchange(&m, nameserver+":53")
	if err != nil {
		return nil, err
	}

	var recordData []string
	if r.Rcode == dns.RcodeSuccess {
		if len(r.Answer) > 0 {
			recordData = parseNS(r.Answer)
		} else {
			// if no NS records are found, fallback to using the authority section
			recordData = parseNS(r.Ns)
		}
	} else {
		return nil, fmt.Errorf("failed to get authoritative servers; Rcode: %d", r.Rcode)
	}

	return recordData, nil
}

// authorityReturnRefusedOrServfail returns true if at least one of the domain's authoritative nameservers
// returns a REFUSED/SERVFAIL response when queried for the domain
func authorityReturnRefusedOrServfail(domain string) (bool, error) {
	// EffectiveTLDPlusOne considers the root domain "." an additional TLD
	// so for "example.com.", it returns "com."
	// but for "example.com" (without trailing "."), it returns "example.com"
	// so we use unFqdn() to remove the trailing dot
	apex, err := publicsuffix.EffectiveTLDPlusOne(unFqdn(domain))
	if err != nil {
		return false, err
	}

	apexAuthority, err := getAuthorityForDomain(apex, dnsServer)
	if err != nil {
		return false, err
	}
	if len(apexAuthority) == 0 {
		return false, fmt.Errorf("couldn't find the apex's nameservers")
	}

	domainAuthority, err := getAuthorityForDomain(domain, apexAuthority[0])
	if err != nil {
		return false, err
	}

	for _, nameserver := range domainAuthority {
		vulnerable, err := nameserverReturnsRefusedOrServfail(domain, nameserver)
		if err != nil {
			// TODO: report this kind of error to the caller?
			continue
		}
		if vulnerable {
			return true, nil
		}
	}
	return false, nil
}

// nameserverReturnsRefusedOrServfail returns true if the given nameserver
// returns a REFUSED/SERVFAIL response when queried for the domain
func nameserverReturnsRefusedOrServfail(domain string, nameserver string) (bool, error) {
	client := dns.Client{}
	message := dns.Msg{}

	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := client.Exchange(&message, nameserver+":53")
	if err != nil {
		return false, err
	}
	if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
		return true, nil
	}
	return false, nil
}

// Now, for each entry in the data providers file, we will check to see if the output
// from the dig command against the current domain matches the CONTENT for that data provider
// if it matches the CONTENT, we need to now check if it matches the string for that data provider
// So, we curl it and see if it matches. At this point, we know its vulnerable
func checkContentAgainstProviders(domain string, content string, cmsRecords []*CMS, config Configuration) []DomainScan {
	transport := &http.Transport{
		Dial:                (&net.Dialer{Timeout: 10 * time.Second}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}}

	client := &http.Client{Transport: transport, Timeout: time.Duration(20 * time.Second)}
	var scanResults []DomainScan

	for _, cmsRecord := range cmsRecords {
		isWildcardProvider := strings.Contains(cmsRecord.Content, "*")
		usesprovider, _ := regexp.MatchString(cmsRecord.Content, content)
		if isWildcardProvider || usesprovider {
			scanResult := evaluateDomainProvider(domain, content, cmsRecord, client)
			if *config.takeOver && scanResult.IsInactive {
				isTakenOver, err := takeOverSub(scanResult.Domain, scanResult.Provider, config)
				if err != nil {
					scanResult.Response = err.Error()
				}
				scanResult.IsTakenOver = isTakenOver
			}
			scanResults = append(scanResults, scanResult)
			if scanResult.IsInactive {
				break
			}
		}
	}
	return scanResults
}

// If there is a content and can't curl it, we will assume its vulnerable
// If we can curl it, we will regex match the string obtained in the response with
// the string specified in the data providers file to see if its vulnerable or not
func evaluateDomainProvider(domain string, content string, cmsRecord *CMS, client *http.Client) DomainScan {
	scanResult := DomainScan{Domain: domain, Content: content,
		IsTakenOver: false, IsInactive: false, Provider: cmsRecord.Name}
	protocol := "https://"
	if cmsRecord.OverHTTP == "true" {
		protocol = "http://"
	}
	response, err := client.Get(protocol + scanResult.Domain)

	if err != nil {
		scanResult.IsInactive = true
		if strings.Contains(strings.ToLower(err.Error()), "Client.Timeout exceeded while awaiting headers") {
			scanResult.Response = "Can't CURL it. err: Client.Timeout exceeded while awaiting headers"
		} else if strings.Contains(strings.ToLower(err.Error()), "timeout") {
			scanResult.Response = "Can't CURL it. err: timeout"
		} else if strings.Contains(strings.ToLower(err.Error()), "no such host") {
			scanResult.Response = "Can't CURL it. err: no such host"
		} else if strings.Contains(strings.ToLower(err.Error()), "tls handshake failure") {
			scanResult.Response = "Can't CURL it. err: tls handshake failure"
		} else {
			scanResult.Response = fmt.Sprintf("Can't CURL it. err: %v", err)
		}
	} else {
		text, err := io.ReadAll(response.Body)
		if err != nil {
			scanResult.Response = err.Error()
		} else {
			scanResult.IsInactive, err = regexp.MatchString(cmsRecord.String, string(text))
			if err != nil {
				scanResult.Response = err.Error()
			} else {
				scanResult.Response = cmsRecord.String
			}
		}
	}
	return scanResult
}

func loadProviders(recordsFilePath string) []*CMS {
	clientsFile, err := os.OpenFile(recordsFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	showUsageOnError(err)
	defer clientsFile.Close()

	cmsRecords := []*CMS{}
	err = gocsv.UnmarshalFile(clientsFile, &cmsRecords)
	showUsageOnError(err)
	return cmsRecords
}

func writeResultsToCsv(scanResults []DomainScan, outputFilePath string) {
	outputFile, err := os.Create(outputFilePath)
	panicOnError(err)
	defer outputFile.Close()

	err = gocsv.MarshalFile(&scanResults, outputFile)
	panicOnError(err)
}

func printResults(scanResults []DomainScan) {
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Domain", "Content", "Provider", "Is Inactive", "Taken Over", "Response"})

	for _, scanResult := range scanResults {
		if (len(scanResult.Content) > 0 && len(scanResult.Provider) > 0) || len(scanResult.Response) > 0 {
			table.Append([]string{scanResult.Domain, scanResult.Content, scanResult.Provider,
				strconv.FormatBool(scanResult.IsInactive),
				strconv.FormatBool(scanResult.IsTakenOver),
				scanResult.Response})
		}
	}
	table.Render()
}
