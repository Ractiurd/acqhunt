# AcqHunt - Acquisition Hunt for Bug Bounty

**AcqHunt** (short for Acquisition Hunt) is a command-line tool designed to help bug bounty hunters and cybersecurity professionals gather information about acquisitions related to a specific email address like Admin email or Registrant mail. It does this by querying two popular websites, **viewdns.info** and **website.informer.com**, **crt.sh** and extracting domain names associated with the provided email address. This script can be a valuable asset for expanding your scope and finding potential targets in bug bounty programs.

## Installation
To install this Tool please use the following Command:
```
https://github.com/Ractiurd/acqhunt.git
cd acqhunt
go build .
```


# Usage:
```
acqhunt [-v] [-i] [-c] -d <domain_name>

- -v: Use this flag to gather acquisitions from viewdns.info.
- -i: Use this flag to gather acquisitions from website.informer.com.
- -d <domain>: Specify the domain name for which you want to gather acquisitions.
- -c: Use this flag to gather acquisitions from crt.sh.
```

Example:

Gather acquisitions from both sources for the example.com:
```
acqhunt -d example.com
```

Gather acquisitions from any single source for the domain address example.com:

```
acqhunt -d example@example.com -i
acqhunt -d example@example.com -v
acqhunt -d example@example.com -c
```


# How AcqHunt Works:

AcqHunt performs the following steps to gather acquisitions:

1. User Input: You provide the address (-d) for which you want to gather acquisitions. It collect the email by itself and bring out you the result

2. Website Selection: AcqHunt allows you to select the sources of acquisitions using the -v and -i and -c flags. If none of these flags are provided, it defaults to using three sources.

3. crt.sh Acquisition (Optional): If the -c flag is set, AcqHunt queries crt.sh to find acquisitions related to the provided domain certificate org name

4. ViewDNS Acquisition (Optional): If the -v flag is set, AcqHunt queries viewdns.info to find acquisitions related to the provided email address.

5. Website Informer Acquisition (Optional): If the -i flag is set, AcqHunt queries website.informer.com to find acquisitions related to the provided email address.

6. Output: The extracted domain names are displayed in the console, which you can further analyze for potential bugs or vulnerabilities in bug bounty programs..

# Disclaimer:

AcqHunt is a tool designed for legitimate security research and bug bounty hunting. Ensure that you have proper authorization and adhere to responsible disclosure policies before using it on any target. so use it responsibly and ethically.

## Question
If you have an question you can create an Issue or ping me on [Ractiurd](https://twitter.com/ractiurd)
