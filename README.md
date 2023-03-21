# Nessus Crosswalk for CISA Known Exploited Vulnerabilities (KEV)

nessus_crosswalk is a capability that returns vulnerability results from Nessus scans that map to the most recent CISA KEV catalog. The output is a sorted list of CVE IDs, based on number of occurrences in the Nessus scans, in the following format: ```{"CVE-####-#####": Number_of_Occurrences}```. 
## Install 
```
$ git clone https://github.com/ajread4/nessus_crosswalk.git
$ cd nessus_crosswalk/
$ pip install -r requirements.txt 
```
## Usage 
```
$ python3 crosswalk.py -h
usage: crosswalk.py [-h] nessus_scan

nessus_crosswalk - a capability that returns vulnerability results from Nessus scans that map to the CISA KEV catalog

positional arguments:
  nessus_scan  specify the input nessus scan, must be .csv

optional arguments:
  -h, --help   show this help message and exits
```
## Example Usage
```
$ python3 crosswalk.py nessus_scan.csv
Stats for nessus_scan.csv: {"CVE-2019-0211":2,"CVE-2019-11043":2,"CVE-2021-40438": 2}
```
## CISA Known Exploited Vulnerabilities Catalog
The CISA Known Exploited Vulnerabilities (KEV) can be found [here](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). The catalog is able to be downloaded as a csv or json.  
## Author
All code was written by AJ Read [ajread4](https://github.com/ajread4). 