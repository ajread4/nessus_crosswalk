# Pull the most recent KEV catalog 

import argparse
import requests
import os 
import pandas as pd 
import urllib.request 
import json
import xmltodict

def main():
    """
    	Main function for crosswalk
    """
    parser = argparse.ArgumentParser(
        description='nessus_crosswalk - a capability that returns vulnerability results from Nessus scans that map to the CISA KEV catalog')
    parser.add_argument('nessus_scan' ,action='store',help='specify the input nessus scan, must be .csv')
    args=parser.parse_args()

    if (determine_filetype(args.nessus_scan)): 
    	stats=create_stats_csv(args.nessus_scan)
    	print(f'Stats for {args.nessus_scan}: {stats}')
    else:
    	print(f'Improper File Type {args.nessus_scan}')

"""
Determine the type of nmap file 
"""
def determine_filetype(input_file):
	if os.path.splitext(input_file)[1] == ".csv":
		print("[+] Requested Statistics for valid file")
		return True 
	else: 
		print("[+] Requested Statistics for invalid file, must be .csv")
		return False 

"""
Count occurrences of CVE IDs in Nessus scan
"""
def create_stats_csv(scan_output):
	stats_db={}
	kev_df=pulldown_json()
	scan_df=pd.read_csv(scan_output)

	# Loop through each row in the Nessus Scan 
	for scan_row in scan_df.itertuples():
		if not pd.isnull(scan_row.CVE) and scan_row.CVE in list(kev_df['cveID']):
			#print(f'Found: {scan_row.CVE}')
			if not scan_row.CVE in stats_db:
				stats_db[scan_row.CVE]=1
			else: 
				old_value=stats_db[scan_row.CVE]
				stats_db[scan_row.CVE]=old_value + 1
	return sorted(stats_db.items(), key=lambda x: x[1], reverse=True)

"""
Pull down the JSON version of the most-recent CISA KEV catalog in JSON format and convert to Pandas DataFrame
"""
def pulldown_json():
	URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
	r=requests.get(URL)
	full_df=pd.DataFrame(json.loads(r.text))
	return full_df['vulnerabilities'].apply(pd.Series)

"""
Call main function
"""
if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(repr(err))