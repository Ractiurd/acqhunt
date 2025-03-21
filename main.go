package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

)



func writeOutput(outputFile *os.File, output string) {
	if outputFile != nil {
		_, err := outputFile.WriteString(output)
		if err != nil {
			log.Fatalf("Error writing to output file: %v", err)
		}
	} else {
		fmt.Print(output)
	}
}

func displayLoadingSpinner(stopChan chan struct{}, wg *sync.WaitGroup, messageChan chan string) {
	defer wg.Done()
	spinnersLeft := []string{"🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"}

	message := "Grabbing acquisitions..."
	for {
		for i := 0; i < len(spinnersLeft); i++ {
			select {
			case <-stopChan:
				fmt.Printf("\r✅ Acquisitions stored\n")
				return
			case msg := <-messageChan:
				message = msg
			default:
				fmt.Printf("\r%s %s ", spinnersLeft[i], message)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}


func main() {
	// Define command line flags
	domainFlag := flag.String("d", "", "Specify the domain to check for acquisitions")
	ipRange := flag.String("ip", "", "Specify the IP range in CIDR notation to fetch unique domains associated with the IP range")
	orgFlag := flag.String("org", "", "Specify the organization to fetch acquisitions")
	asnPtr := flag.String("a", "", "Specify the ASN number to fetch unique domains associated with the ASN")
	outputFlag := flag.String("o", "", "Specify the output file path. If provided, the output will be written to this file.")

	// Define boolean flags
	var  useWebsiteInformer, crtsh,  orgcrt, whoisdomain bool
	flag.BoolVar(&useWebsiteInformer, "i", false, "Fetch results from website.informer.com")
	flag.BoolVar(&crtsh, "c", false, "Fetch results from domain to crt.sh")
	flag.BoolVar(&orgcrt, "oc", false, "Fetch results from org to crt.sh")
	flag.BoolVar(&whoisdomain, "w", false, "Fetch results from domain to reveresewhois")

	// Define usage function for the command line flags
	flag.Usage = func() {
		fmt.Println("Usage: AcqHunt [Created by Ractiurd]")
		fmt.Println("\nOptions:")
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("  -%s %s\n", f.Name, f.Usage)
		})
	}

	// Parse command line flags
	flag.Parse()

	// Check if no flags are provided
	if *domainFlag == "" && *orgFlag == "" && *ipRange == "" && *asnPtr == "" {
		fmt.Println("Usage: go run main.go (-d <domain> | -o <org> | -ip <IP range> | -a <ASN number>)")
		return
	}

	// Open the output file if provided
	var outputFile *os.File
	if *outputFlag != "" {
		var err error
		outputFile, err = os.Create(*outputFlag)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer outputFile.Close()
	}



	// Continue with the program execution based on provided flags
	stopChan := make(chan struct{})
	messageChan := make(chan string)
	var wg sync.WaitGroup
	if *outputFlag != "" {
		wg.Add(1)
		go displayLoadingSpinner(stopChan, &wg, messageChan)
	}

	// Function to signal completion of background work
	signalCompletion := func() {
		if *outputFlag != "" {
			messageChan <- fmt.Sprintf("Acquisitions stored to %s", *outputFlag)
			time.Sleep(1 * time.Second) // Give time for the final message to display
			close(stopChan)
			wg.Wait()
		}
	}

	// Check if ASN flag is provided


	if *asnPtr != "" {
		err := printUniqueDomainsForASN(*asnPtr, func(output string) { writeOutput(outputFile, output) })
		if err != nil {
			fmt.Printf("Error printing unique domains for ASN: %v\n", err)
		}
		signalCompletion()
		return
	}

	if *ipRange != "" {
		err := printUniqueDomains(*ipRange, func(output string) { writeOutput(outputFile, output) })
		if err != nil {
			fmt.Printf("Error printing unique domains: %v\n", err)
		}
		signalCompletion()
		return
	}

	if *orgFlag != "" {
		orgName := *orgFlag // Dereference the pointer to get the string value
		

		var domains []string
		



		if orgcrt {
			// Fetch domains using fetchUniqueDomains function
			uniqueDomains := fetchUniqueDomains(orgName)
			for domain := range uniqueDomains {
				domains = append(domains, domain)
			}
		}

		
	} else {
		if !useWebsiteInformer && !crtsh && !whoisdomain {
	
			useWebsiteInformer = true
			crtsh = true
			whoisdomain = true
		}

		if crtsh {
			if !crtsh1(*domainFlag, func(output string) { writeOutput(outputFile, output) }) {
				writeOutput(outputFile, "Unable to gather Acquisitions from crt.sh\n")
			}
		}

		if useWebsiteInformer || whoisdomain {
			email, err := getEmail(domainFlag)
			if err != nil {
				writeOutput(outputFile, fmt.Sprintf("Error getting email: %v\n", err))
				return
			}


			if useWebsiteInformer {
				if !processWebsiteInformer(email, func(output string) { writeOutput(outputFile, output) }) {
					writeOutput(outputFile, "Unable to gather Acquisitions from website.informer.com\n")
				}
			}
			if whoisdomain {
				email, err := getEmail(domainFlag)
				if err != nil {
					writeOutput(outputFile, fmt.Sprintf("Error getting email: %v\n", err))
					return
				}

				domains, err := whoisSearch(email)
				if err != nil {
					writeOutput(outputFile, fmt.Sprintf("Error searching WHOIS: %v\n", err))
					return
				}

				// Process domains (write to output, etc.)
				for _, domain := range domains {
					writeOutput(outputFile, fmt.Sprintf("%s\n", domain))
				}
			}
		}
	}

	// Signal completion of the background work
	signalCompletion()
}

func fetchUniqueDomains(companyName string) map[string]struct{} {

	if strings.Contains(companyName, " ") {
		companyName = strings.Replace(companyName, " ", "+", -1)
		
	}
	// Create the URL for the crt.sh query
	url := fmt.Sprintf("https://crt.sh/?q=%s", companyName)
	

	// Execute curl command to fetch data
	cmd := exec.Command("curl", "-s", url)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error fetching data: %v\n", err)
		return nil
	}

	// // Debug: Print command output
	// fmt.Println("Curl Output:", string(output))

	// Define the first regex pattern to extract data between <TD> tags
	pattern := `<TD>\s*([^<]+)\s*</TD>`

	// Compile the first regex pattern
	re := regexp.MustCompile(pattern)

	// Find all matches in the command output
	matches := re.FindAllStringSubmatch(string(output), -1)

	// Debug: Print regex matches
	//fmt.Println("Regex Matches:", matches)

	// Define the second regex pattern to extract values from the first regex matches
	regex2 := `\b([\w.-]+(?:\.[a-z]{2,})+)\b`
	secondRe := regexp.MustCompile(regex2)

	// Create a map to track unique domains
	uniqueDomains := make(map[string]struct{})

	// Loop through the matches of the first regex and apply the second regex to each match
	for _, match := range matches {
		if len(match) > 1 {
			firstMatch := match[1]
			secondMatches := secondRe.FindAllStringSubmatch(firstMatch, -1)
			if len(secondMatches) > 0 && len(secondMatches[0]) > 1 {
				// Extract the main domain from the second regex output
				domain := extractMainDomain(secondMatches[0][1])
				// Check if the domain is unique before adding it to the map
				if _, found := uniqueDomains[domain]; !found {
					//fmt.Println(domain)
					uniqueDomains[domain] = struct{}{} // Mark the domain as seen
				}
			}
		}
	}

	return uniqueDomains

}



func crtsh1(url string, writeOutput func(string)) bool {
	org, err := getOrganization(url)
	if err != nil {
		writeOutput(fmt.Sprintf("Error: %v\n", err))
		return false
	}

	uniqueDomains := fetchUniqueDomains(org)

	for domain := range uniqueDomains {
		writeOutput(fmt.Sprintf("%s\n", domain))
	}

	return true
}



func scrapeEmailsFromWeb(domain string) ([]string, error) {
	url := "https://website.informer.com/" + domain 
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request failed with status code: %d", response.StatusCode)
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	regexPattern := (`(?i)<h4[^>]*>\s*Owner Emails\s*</h4>\s*<p[^>]*>\s*<a[^>]*href="[^"]*email/([^"]+)"`)
	regex := regexp.MustCompile(regexPattern)
	matches := regex.FindAllStringSubmatch(string(responseBody), -1)

	emails := []string{}
	for _, match := range matches {
		if len(match) > 1 {
			emails = append(emails, match[1])
		}
	}

	if len(emails) == 0 {
		emails = append(emails, "no_email_found")
	}

	return emails, nil
}

func performWhoisLookup(domain string) (string, error) {
	cmd := "bash"
	whoisArgs := []string{"-c", fmt.Sprintf("whois %s | grep 'Registrant Email' | egrep -ho '[[:graph:]]+@[[:graph:]]+'", domain)}
	whoisOutput, err := exec.Command(cmd, whoisArgs...).Output()
	if err != nil || len(strings.TrimSpace(string(whoisOutput))) == 0 {
		return "no_email_found", nil
	}

	whoisLines := strings.Split(strings.TrimSpace(string(whoisOutput)), "\n")
	if len(whoisLines) == 0 {
		return "no_email_found", nil
	}

	return whoisLines[0], nil
}



func processWebsiteInformer(email string, writeOutput func(string)) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://website.informer.com/email/%s", email)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		writeOutput(fmt.Sprintf("Error creating request for website.informer.com: %v\n", err))
		return false
	}

	req.Header.Set("Host", "website.informer.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		writeOutput(fmt.Sprintf("Error making request to website.informer.com: %v\n", err))
		return false
	}
	defer resp.Body.Close()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		writeOutput(fmt.Sprintf("Error reading response body from website.informer.com: %v\n", err))
		return false
	}

	checkValue := "This page has moved"
	if strings.Contains(string(bodyText), checkValue) {
		writeOutput("The page has moved\n")
		return false
	}

	reAnchorTextFill := regexp.MustCompile(`title="([a-zA-Z0-9.-]+\.com)`)
	reDomain := regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]+\b`)
	reEmailID := regexp.MustCompile(`email-id="(\d+)"`)
	reSiteID := regexp.MustCompile(`site-id="(\d+)"`)

	matchesAnchorTextFill := reAnchorTextFill.FindAllStringSubmatch(string(bodyText), -1)
	textValues := []string{}

	for _, match := range matchesAnchorTextFill {
		textValue := match[1]
		textValues = append(textValues, textValue)
	}

	allText := strings.Join(textValues, " ")
	domainMatches := reDomain.FindAllString(allText, -1)

	for _, domain := range domainMatches {
		writeOutput(fmt.Sprintf("%s\n", domain))
	}

	matchEmailID := reEmailID.FindStringSubmatch(string(bodyText))
	if len(matchEmailID) > 1 {
		
		emailID := matchEmailID[1]
		matchesSiteID := reSiteID.FindAllStringSubmatch(string(bodyText), -1)
		siteIDs := []string{}

		for _, match := range matchesSiteID {
			siteID := match[1]
			
			siteIDs = append(siteIDs, siteID)
		}

		num := 10

		for {
			siteIDList := strings.Join(siteIDs, ",")
			secondURL := fmt.Sprintf("https://website.informer.com/ajax/email/sites?email_id=%s&sort_by=popularity&skip=%s,&max_index=%d", emailID, siteIDList, num)
			
			req2, err := http.NewRequest("GET", secondURL, nil)
			if err != nil {
				writeOutput(fmt.Sprintf("Error creating second request for website.informer.com: %v\n", err))
				return false
			}
			req2.Header.Set("Host", "website.informer.com")
			req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0")
			req2.Header.Set("Connection", "close")

			resp2, err := client.Do(req2)
			if err != nil {
				writeOutput(fmt.Sprintf("Error making second request to website.informer.com: %v\n", err))
				return false
			}
			defer resp2.Body.Close()

			num += 10

			bodyText2, err := io.ReadAll(resp2.Body)
			
			if err != nil {
				writeOutput(fmt.Sprintf("Error reading second response body from website.informer.com: %v\n", err))
				return false
			}


			targetString := `"showMore":false`
			

			if strings.Contains(string(bodyText2), targetString) {
				break
				}else {
					// First regex to extract the entire title attribute value
					reDomain := regexp.MustCompile(`title=\\"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)

					// Find all matches for the domain names in the response body
					domainMatches := reDomain.FindAllStringSubmatch(string(bodyText2), -1)
					
					// Debug: Print the matches found by the regex

					
					// Iterate over each match and extract the domain name
					for _, match := range domainMatches {
						if len(match) > 1 {
							domainName := match[1]
							// Debug: Print the extracted domain name
							// Write the extracted domain name to the output
							writeOutput(fmt.Sprintf("%s\n", domainName))
						}
					}
					

	
					reSiteID2 := regexp.MustCompile(`site-id=\\"(\d+)\\"`)
					matchesSiteID2 := reSiteID2.FindAllStringSubmatch(string(bodyText2), -1)
	
					for _, match := range matchesSiteID2 {
						siteID2 := match[1]
						
						siteIDs = append(siteIDs, siteID2)
					}
				}
			//
		}
	}

	return true
}

func getOrganization(url string) (string, error) {
	conn, err := tls.Dial("tcp", url+":443", &tls.Config{})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	certificates := conn.ConnectionState().PeerCertificates

	if len(certificates) == 0 {
		return "", fmt.Errorf("No certificates found")
	}

	certificate := certificates[0]
	org := certificate.Subject.Organization

	if len(org) == 0 {
		return "", fmt.Errorf("Organization (O) not found in the certificate")
	}

	orgName := org[0]
	fmt.Println("Organization Name : ",  orgName)

	// Check if orgName contains spaces, and if so, replace them with '+'
	if strings.Contains(orgName, " ") {
		orgName = strings.Replace(orgName, " ", "+", -1)
	}
	

	return orgName, nil
}

// Function to extract the main domain from a URL
func extractMainDomain(url string) string {
	parts := strings.Split(url, ".")
	// Check if the URL has at least two parts (e.g., "example.com")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return url // Return the original URL if it doesn't have a main domain.
}

func getEmail(domainFlag *string) (string, error) {
	var email string

	webEmails, webErr := scrapeEmailsFromWeb(*domainFlag)
	if webErr != nil {
		return "", webErr
	}

	whoisEmail, whoisErr := performWhoisLookup(*domainFlag)
	if whoisErr != nil {
		return "", whoisErr
	}

	// Check if both email addresses are the same
	if webEmails[0] == whoisEmail {
		email = webEmails[0]
	} else {
		fmt.Println("1", webEmails[0])
		fmt.Println("2", whoisEmail)

		fmt.Print("Which one do you want to proceed with? (1/2): \n\n If you want to exit, press Enter \n >> ")
		var choice string
		fmt.Scanln(&choice)

		if choice == "1" {
			email = webEmails[0]
		} else if choice == "2" {
			email = whoisEmail
		} else if choice == "" {
			fmt.Println("Have a wonderful day, sir")
			os.Exit(0)
		}
	}

	return email, nil
}
func printUniqueDomains(ipRange string, writeOutput func(string)) error {
	// Execute the command
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | dnsx -resp-only -ptr", ipRange))
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Process and write the unique domain names
	lines := strings.Split(string(output), "\n")
	uniqueLines := make(map[string]bool)
	for _, line := range lines {
		parts := strings.Split(line, ".")
		if len(parts) >= 2 {
			domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
			uniqueLines[domain] = true
		}
	}
	for domain := range uniqueLines {
		writeOutput(fmt.Sprintf("%s\n", domain))
	}

	return nil
}
func printUniqueDomainsForASN(asn string, writeOutput func(string)) error {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("asnmap -a %s -silent", asn))
	var final []interface{}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error running asnmap command: %v", err)
	}

	asnInfo := strings.Split(string(output), "\n")
	for _, line := range asnInfo {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cmd := exec.Command("bash", "-c", fmt.Sprintf("echo \"%s\" | dnsx -resp-only -ptr", line))
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Error running dnsx command for IP %s: %v", line, err)
			continue
		}

		lines := strings.Split(string(output), "\n")
		uniqueDomains := make(map[string]bool)

		for _, dnsLine := range lines {
			dnsLine = strings.TrimSpace(dnsLine)
			if dnsLine == "" {
				continue
			}
			parts := strings.Split(dnsLine, ".")
			if len(parts) >= 2 {
				domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
				uniqueDomains[domain] = true
			}
		}

		for domain := range uniqueDomains {
			final = append(final, domain)
		}
	}

	uniqueValues := make(map[interface{}]bool)
	for _, value := range final {
		uniqueValues[value] = true
	}

	writeOutput("Unique values:\n")
	for value := range uniqueValues {
		writeOutput(fmt.Sprintf("%v\n", value))
	}

	return nil
}

type ConfigWhois struct {
	APIKey string `yaml:"apiKey"`
}

// Define the API URL
const apiURL = "https://reverse-whois.whoisxmlapi.com/api/v2"

// ReverseWhoisRequest struct for API request body
type ReverseWhoisRequest struct {
	APIKey           string `json:"apiKey"`
	SearchType       string `json:"searchType"`
	Mode             string `json:"mode"`
	Punycode         bool   `json:"punycode"`
	BasicSearchTerms struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	} `json:"basicSearchTerms"`
}

// ReverseWhoisResponse struct for API response
type ReverseWhoisResponse struct {
	NextPageSearchAfter interface{} `json:"nextPageSearchAfter"`
	DomainsCount        int         `json:"domainsCount"`
	DomainsList         []string    `json:"domainsList"`
}

// Function to perform WHOIS search including configuration management
func whoisSearch(email string) ([]string, error) {
	// Default API key path
	homeDir, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("error getting user's home directory: %v", err)
	}
	configDir := filepath.Join(homeDir.HomeDir, ".config", "acqhunt")

	// Ensure the .config/acqhunt directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err = os.MkdirAll(configDir, 0755)
		if err != nil {
			return nil, fmt.Errorf("error creating directory %s: %v", configDir, err)
		}
	}

	apiKeyPath := filepath.Join(configDir, "whoisxml.yaml")

	// Load or prompt for API key
	var config ConfigWhois
	data, err := ioutil.ReadFile(apiKeyPath)
	if err == nil {
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling config file: %v", err)
		}
	}

	// Prompt user for API key if not found
	if config.APIKey == "" {
		fmt.Println("Whoisxml API key not found in configuration file. Please enter your API key:")
		fmt.Scanln(&config.APIKey)
		data, err := yaml.Marshal(&config)
		if err != nil {
			return nil, fmt.Errorf("error marshaling config: %v", err)
		}
		err = ioutil.WriteFile(apiKeyPath, data, 0644)
		if err != nil {
			return nil, fmt.Errorf("error writing config file: %v", err)
		}
		fmt.Println("API key saved to configuration file.")
	}

	// Create the request body
	requestBody := ReverseWhoisRequest{
		APIKey:     config.APIKey,
		SearchType: "current",
		Mode:       "purchase",
		Punycode:   true,
	}
	requestBody.BasicSearchTerms.Include = []string{email}

	// Marshal the request body to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Parse the JSON response
	var response ReverseWhoisResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	// Return the list of domains
	return response.DomainsList, nil
}

