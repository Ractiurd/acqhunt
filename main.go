package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

func main() {
	var useViewDNS, useWebsiteInformer bool
	flag.BoolVar(&useViewDNS, "v", false, "Use -v to get results from viewdns.info")
	flag.BoolVar(&useWebsiteInformer, "i", false, "Use -i to get results from website.informer.com")
	email := flag.String("e", "", "Email address to gather Acquisitions")
	flag.Parse()

	if *email == "" {
		fmt.Println("You did not provide an email address.")
		return
	}

	if !useViewDNS && !useWebsiteInformer {
		useViewDNS = true
		useWebsiteInformer = true
	}

	if useViewDNS {
		if !processViewDNS(*email) {
			fmt.Println("Unable to gather Acquisitions from viewdns.info")
		}
	}

	if useWebsiteInformer {
		if !processWebsiteInformer(*email) {
			fmt.Println("Unable to gather Acquisitions from website.informer.com")
		}
	}
}

func processViewDNS(email string) bool {
	url := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", email)
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

func processWebsiteInformer(email string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://website.informer.com/email/%s", email)
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
