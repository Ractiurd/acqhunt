# Stand With Palestine

![Palestinian Flag](https://img.freepik.com/premium-photo/child-holding-palestinian-flag-front-destroyed-building_988987-10735.jpg)

The current situation in Palestine is heartbreaking, with Israel committing acts of genocide and many more atrocities against innocent Palestinians. Thousands of lives have been lost, and entire communities are being destroyed. The massacre must be stopped, and we, as global citizens, must not stay silent. We need to raise our voices, spread awareness, and stand with Palestine in this dire moment.

Let us all make dua (pray) for the people of Palestine and do our part in calling for an end to these injustices. This is not just a political issue—it is a humanitarian crisis that requires our collective attention and action.

Please take a moment to reflect on this cause and spread awareness. Stand with Palestine!



---

# AcqHunt

AcqHunt is a versatile reconnaissance tool designed for discovering acquisitions and related information associated with domains, IP addresses, organizations, and ASN numbers. This command-line utility provides a comprehensive suite of features tailored for cybersecurity professionals, researchers, and enthusiasts alike.

## Features

- **ASN Lookup (`-a`)**: Fetches unique domains associated with the specified Autonomous System Number (ASN).
  
- **Domain Search (`-d`)**: Investigates acquisitions related to the specified domain name.
  
- **IP Range Analysis (`-ip`)**: Identifies unique domains linked to the specified IP range in CIDR notation.
  
- **Organization Search (`-org`)**: Retrieves acquisitions involving the specified organization.
  
- **Output Options (`-o`)**: Allows exporting results to a specified file for further analysis and reporting.
  
### Additional Capabilities

- **Crt.sh Integration (`-c`, `-oc`)**: Fetches data from crt.sh, providing comprehensive insights into domain certificates and acquisitions related to domains or organizations.
  
- **Website Informer (`-i`)**: Gathers data from website.informer.com to supplement acquisition research.
  
- **Shodan Integration (`-s`)**: Retrieves relevant information from Shodan, offering insights into connected devices and infrastructure.
  
- **ViewDNS Info (`-v`)**: Provides additional context from viewdns.info, enhancing the understanding of domain and IP address relationships.
  
- **Reverse WHOIS (`-w`)**: Utilizes reverse WHOIS lookup to identify domains associated with specific registrants, aiding in comprehensive acquisition analysis.

## Usage

AcqHunt empowers users to conduct thorough reconnaissance on acquisitions across various digital assets, leveraging multiple sources to compile actionable intelligence. Whether assessing acquisitions from specific domains, IP addresses, organizations, or ASN numbers, AcqHunt offers a seamless and powerful solution for cybersecurity professionals and researchers seeking to enhance their investigative capabilities.

## Installation

To install AcqHunt, use the following `go install` command:

```bash
go install github.com/ractiurd/acqhunt@latest
```
This will download and install the latest version of AcqHunt on your system.

Once installed, you can run the tool using:
```bash
acqhunt -h
```
Manual Installation
If you prefer to install manually, follow these steps:
```bash
# Clone the repository
git clone https://github.com/ractiurd/acqhunt.git

# Navigate to the project directory
cd acqhunt

# Build the binary
go build .

# Move the binary to /usr/bin for system-wide access
sudo mv acqhunt /usr/bin/
```

## Licensing

AcqHunt offers a trial period of 15 uses for users to evaluate its capabilities. To continue using the tool beyond the trial period, you will need to obtain a license key from the author.

For licensing inquiries and more information, please contact [ractiurd] via visiting [x.com/ractiurd](https://x.com/ractiurd) or [facebook.com/ractiurd](https://facebook.com/ractiurd) and message him directly.
