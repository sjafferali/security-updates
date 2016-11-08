#!/usr/bin/python
#
# Currently only lists out the packages that have security updates
# 
import json
import os
import requests
import sys

API_HOST = 'https://access.redhat.com/labs/securitydataapi'
endpoint = '/cve.json'


def get_data(query):

    full_query = API_HOST + query
    r = requests.get(full_query)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, full_query))
        sys.exit(1)

    return r.json()


with os.popen('yum check-update --disableexcludes=all -q | awk \'/\s+updates\s*$/ {print$1"-"$2}\' | sed -e "s,.x86_64,,g" -e "s,.noarch,,g"') as package:
    for line in package:
	params = 'package='+line.strip()
	data = get_data(endpoint + '?' + params)
	subdata=json.dumps(data)
	if len(json.loads(subdata)) > 0:
            print line.strip()
	    for cve in json.loads(subdata):
		if cve['severity'] == "important":
                	print "\t- "+cve['CVE']+"\t"+cve['severity']+"\t"+"https://access.redhat.com/security/cve/"+cve['CVE']
	    for cve in json.loads(subdata):
                if cve['severity'] == "moderate":
                        print "\t- "+cve['CVE']+"\t"+cve['severity']+"\t"+"https://access.redhat.com/security/cve/"+cve['CVE']
	    for cve in json.loads(subdata):
                if cve['severity'] == "low":
                        print "\t- "+cve['CVE']+"\t"+cve['severity']+"\t\t"+"https://access.redhat.com/security/cve/"+cve['CVE']
