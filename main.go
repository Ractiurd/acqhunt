package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func main() {
	domainFlag := flag.String("d", "", "Specify the domain to check for admin email")
	//
	var useViewDNS, useWebsiteInformer, crtsh bool
	flag.BoolVar(&useViewDNS, "v", false, "Use -v to get results from viewdns.info")
	flag.BoolVar(&useWebsiteInformer, "i", false, "Use -i to get results from website.informer.com")
	flag.BoolVar(&crtsh, "c", false, "Use -c to get results from crt.sh")
	//
	flag.Parse()

	if *domainFlag == "" {
		fmt.Println("Usage: go run main.go -d <domain>")
		return
	}

	//processViewDNS(email)
	//processWebsiteInformer(email)
	//
	if !useViewDNS && !useWebsiteInformer && !crtsh {
		useViewDNS = true
		useWebsiteInformer = true
		crtsh = true

	}
	if crtsh {
		if !crtsh1(*domainFlag) {
			fmt.Println("Unable to gather Acquisitions from crt.sh")
		}

	}
	if useViewDNS || useWebsiteInformer {
		email, err := getEmail(domainFlag)
		if err != nil {
			fmt.Printf("Error getting email: %v\n", err)
			return
		}

		if useViewDNS {
			if !processViewDNS(email) {
				fmt.Println("Unable to gather Acquisitions from viewdns.info")
			}
		}

		if useWebsiteInformer {
			if !processWebsiteInformer(email) {
				fmt.Println("Unable to gather Acquisitions from website.informer.com")
			}
		}
	}

}

func crtsh1(url string) bool {
	org, err := getOrganization(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return false
	}

	// Call the second code with the extracted organization name
	uniqueDomains := fetchUniqueDomains(org)

	// Print the unique domains
	for domain := range uniqueDomains {
		fmt.Println(domain)
	}

	// Return true to indicate success
	return true
}

func scrapeEmailsFromWeb(domain string) ([]string, error) {
	url := "https://website.informer.com/" + domain + "/emails"
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

	regexPattern := `Owner's emails<\/p>\s*<ul>(?:\s*<li>\s*<a href="\/email\/[^"]+" >([^<]+)<\/a>\s*<\/li>)+`
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

func processViewDNS(email1 string) bool {
	url := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", email1)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("Unable to fetch data from viewdns.info:", err)
	}
	defer resp.Body.Close()

	if resp == nil {
		fmt.Print("from viewdnsinfo \n")
		return false
	}

	html, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading HTML from viewdns.info:", err)
	}

	checkValue := "There are 0 domains that matched"
	if strings.Contains(string(html), checkValue) {
		return false
	}

	// Define regular expression patterns
	pattern1 := `<td>(\b[a-zA-Z0-9.-]+\.[a-zA-Z]+\b)</td>`
	pattern2 := `\b[a-zA-Z0-9.-]+\.[a-zA-Z]+\b`

	// Compile regular expressions
	re1 := regexp.MustCompile(pattern1)
	re2 := regexp.MustCompile(pattern2)

	// Find matches in the HTML and extract domain names
	matches1 := re1.FindAllStringSubmatch(string(html), -1)

	for _, match := range matches1 {
		if len(match) > 1 {
			value := match[1]
			matches2 := re2.FindStringSubmatch(value)
			if len(matches2) > 0 {
				fmt.Println(matches2[0])
			}
		}
	}

	return true
}

func processWebsiteInformer(email3 string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://website.informer.com/email/%s", email3)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Error creating request for website.informer.com:", err)
	}

	req.Header.Set("Host", "website.informer.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error making request to website.informer.com:", err)
	}
	defer resp.Body.Close()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response body from website.informer.com:", err)
	}

	checkValue := "This page has moved"
	if strings.Contains(string(bodyText), checkValue) {
		return false
	}

	// Define regular expression patterns
	reAnchorTextFill := regexp.MustCompile(`<a[^>]*\bclass="textfill"[^>]*>(.*?)</a>`)
	reDomain := regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]+\b`)
	reEmailID := regexp.MustCompile(`email-id="(\d+)"`)
	reSiteID := regexp.MustCompile(`site-id="(\d+)"`)

	// Find matches and extract information
	matchesAnchorTextFill := reAnchorTextFill.FindAllStringSubmatch(string(bodyText), -1)
	textValues := []string{}

	for _, match := range matchesAnchorTextFill {
		textValue := match[1]
		textValues = append(textValues, textValue)
	}

	allText := strings.Join(textValues, " ")

	domainMatches := reDomain.FindAllString(allText, -1)

	for _, domain := range domainMatches {
		fmt.Println(domain)
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

			// Make the second request
			req2, err := http.NewRequest("GET", secondURL, nil)
			if err != nil {
				log.Fatal("Error creating second request for website.informer.com:", err)
			}
			req2.Header.Set("Host", "website.informer.com")
			req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0")
			req2.Header.Set("Connection", "close")

			resp2, err := client.Do(req2)
			if err != nil {
				log.Fatal("Error making second request to website.informer.com:", err)
			}
			defer resp2.Body.Close()

			num += 10

			bodyText2, err := io.ReadAll(resp2.Body)
			if err != nil {
				log.Fatal("Error reading second response body from website.informer.com:", err)
			}

			targetString := "\"sites\":\"\""

			if strings.Contains(string(bodyText2), targetString) {
				break
			} else {
				reDomain2 := regexp.MustCompile(`domain=\b[a-zA-Z0-9.-]+\.[a-zA-Z]+\b`)
				reDomainValue := regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]+\b`)

				domainMatches2 := reDomain2.FindAllString(string(bodyText2), -1)

				for _, domain2 := range domainMatches2 {
					domainValue := reDomainValue.FindString(domain2)
					fmt.Println(domainValue)
				}

				reSiteID2 := regexp.MustCompile(`site-id=\\"(\d+)\\"`)
				matchesSiteID2 := reSiteID2.FindAllStringSubmatch(string(bodyText2), -1)

				for _, match := range matchesSiteID2 {
					siteID2 := match[1]
					siteIDs = append(siteIDs, siteID2)
				}
			}
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

	// Check if orgName contains spaces, and if so, replace them with '+'
	if strings.Contains(orgName, " ") {
		orgName = strings.Replace(orgName, " ", "+", -1)
	}

	return orgName, nil
}

func fetchUniqueDomains(companyName string) map[string]struct{} {
	// Create the URL for the crt.sh query
	url := fmt.Sprintf("https://crt.sh/?q=%s", companyName)

	// Send an HTTP GET request to the URL
	response, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching data: %v\n", err)
		return nil
	}
	defer response.Body.Close()

	// Check if the request was successful
	if response.StatusCode != http.StatusOK {
		fmt.Printf("Request failed with status code: %d\n", response.StatusCode)
		return nil
	}

	// Read the response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil
	}

	// Define the first regex pattern to extract data between <TD> tags
	pattern := `<TD>\s*([^<]+)\s*</TD>`

	// Compile the first regex pattern
	re := regexp.MustCompile(pattern)

	// Find all matches in the HTML body
	matches := re.FindAllStringSubmatch(string(body), -1)

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
					uniqueDomains[domain] = struct{}{} // Mark the domain as seen
				}
			}
		}
	}

	return uniqueDomains
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
