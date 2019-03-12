#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# cvedetails-lookup
# --------------
# Perform vulnerabilities lookup on cvedetails.com
#
import argparse
import bs4
import re
import pprint
import sys
import colored
import prettytable
import textwrap
import requests
from distutils.version import LooseVersion
from collections import defaultdict


#------------------------------------------------------------------------------
# Utils functions
#------------------------------------------------------------------------------
def colorize(string, color=None, highlight=None, attrs=None):
    """Apply style on a string"""
    # Colors list: https://pypi.org/project/colored/
    return colored.stylize(string, 
        (colored.fg(color) if color else '') + \
        (colored.bg(highlight) if highlight else '') + \
        (colored.attr(attrs) if attrs else ''))

def remove_non_printable_chars(string):
    """Remove non-ASCII chars like chinese chars"""
    printable = set("""0123456789abcdefghijklmnopqrstuvwxyz"""
        """ABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ """)
    return ''.join(filter(lambda x: x in printable, string))

def table(columns, data, hrules=True):
    """Print a table"""
    columns = map(lambda x:colorize(x, attrs='bold'), columns)
    table = prettytable.PrettyTable(
        hrules=prettytable.ALL if hrules else prettytable.FRAME, 
        field_names=columns)
    for row in data:
        table.add_row(row)
    table.align = 'l'
    print(table)

def shorten(string, maxlength):
    """Shorten a string if it exceeds a given length"""
    if len(string) <= maxlength:
        return string
    else:
        return textwrap.wrap(string, maxlength)[0]+'...'

def get_cvss_score(vuln, vulners_api):
    """Get CVSS score if available, otherwise get Vulners AI score"""
    cvss = r['cvss']['score']

    if cvss == 0.0:
        return vulners_api.aiScore(vuln['description'])[0]
    else:
        return cvss

def color_cvss(cvss):
    """Attribute a color to the CVSS score"""
    cvss = float(cvss)
    if cvss < 3:
        color = 'green_3b'
    elif cvss <= 5:
        color = 'yellow_1'
    elif cvss <= 7:
        color = 'orange_1'
    elif cvss <= 8.5:
        color = 'dark_orange'
    else:
        color = 'red'
    return color

def info(string):
    """Print info message"""
    print(colorize('[*] ', color='light_blue', attrs='bold') + string)

def warning(string):
    """Print warning message"""
    print(colorize('[!] ', color='dark_orange', attrs='bold') + \
        colorize(string, color='dark_orange'))

def error(string):
    """Print warning message"""
    print(colorize('[!] {}'.format(string), color='red', attrs='bold'))

def success(string):
    """Print success message"""
    print(colorize('[+] {}'.format(string), color='green_3b', attrs='bold'))    


#------------------------------------------------------------------------------
# Cvedetails processing functions
#------------------------------------------------------------------------------
def get_closest_superior_version(target_version, list_avail_versions):
    """
    :param target_version: Version number to check for
    :param list_avail_versions: List of version numbers availables on cvedetails

    :return: Minimum of version numbers that are superior to target_version.
             None if not available.
    """
    sup_versions = list()
    for v in list_avail_versions:
        try:
            if LooseVersion(v) >= LooseVersion(target_version):
                sup_versions.append(LooseVersion(v))
        except:
            pass

    if sup_versions:
        return str(min(sup_versions))
    else:
        return None


def retrieve_id_from_link(href, type_id):
    """
    Retrieve id from cvedetails URL
    """
    id_search = re.search('/'+type_id+'/([0-9]+)/', href)
    if not id_search:
        return None
    return id_search.group(1)


def parse_html_table_versions(html):
    """
    Parse HTML results into dict { 'version': [ list of corresponding id ]}
    """
    soup = bs4.BeautifulSoup(html, 'html.parser')
    table_results = soup.find(class_='searchresults')
    versions_results = defaultdict(list)

    for row in table_results.findAll('tr')[1:]:
        col = row.findAll('td')
        #print(col)
        version = col[3].text.strip()

        version_id = retrieve_id_from_link(col[8].find('a')['href'], 'version')
        if version_id:
            versions_results[version].append(version_id)

    return versions_results


def get_ids_from_cve_page(resp, args):
    """
    Get vendor id, product id, version, version id from a CVE results page
    """
    # Parse HTML
    soup = bs4.BeautifulSoup(resp, 'html.parser')
    title_links = soup.find('h1').findAll('a')

    # Retrieve Vendor & Vendor_id
    vendor = args.vendor or title_links[0].text
    vendor_id = retrieve_id_from_link(title_links[0]['href'], 'vendor')
    if not vendor_id:
        error('Error: Unable to get Vendor id !')
        sys.exit(1)

    # Retrieve Product_id
    product_id = retrieve_id_from_link(title_links[1]['href'], 'product')
    if not product_id:
        error('Error: Unable to get Product id !')
        sys.exit(1)

    # Retrieve version_id
    version = title_links[2].text.strip()
    version_id = [retrieve_id_from_link(title_links[2]['href'], 'version')]
    if not version_id:
        error('Error: Unable to get Version id !')
        sys.exit(1)

    return vendor, vendor_id, product_id, version, version_id


def get_ids_from_searchresults(resp, args):
    """
    Get vendor id, product id from first result 
    (first row) from search results page
    """
    soup = bs4.BeautifulSoup(resp, 'html.parser')
    table_results = soup.find(class_='searchresults')

    # Retrieve Vendor id
    row_1 = table_results.findAll('tr')[1]
    vendor_id = retrieve_id_from_link(row_1.findAll('td')[1].find('a')['href'], 'vendor')
    if not vendor_id:
        error('Error: Unable to get Vendor id !')
        sys.exit(1)
    vendor = args.vendor or row_1.findAll('td')[1].find('a').text

    # Retrieve Product id
    product_id = retrieve_id_from_link(row_1.findAll('td')[2].find('a')['href'], 'product')
    if not product_id:
        error('Error: Unable to get Product id !')
        sys.exit(1)

    return vendor, vendor_id, product_id



def request_search(vendor, product, version):
    """
    Send search request on cvedetails.com
    """
    r = requests.get('https://www.cvedetails.com/version-search.php?' \
        'vendor={vendor}&product={product}&version={version}'.format(
            vendor  = vendor,
            product = product,
            version = version))
    return r.text


def is_cve_in_json(cve_id, json):
    for cve in json:
        if cve['cve_id'] == cve_id:
            return True
    return False


def merge_jsons(jsons_list):
    results = list()
    for json in jsons_list:
        for cve in json:
            if not is_cve_in_json(cve['cve_id'], results):
                results.append(cve)
    return results


#------------------------------------------------------------------------------
# Command-line parsing
#------------------------------------------------------------------------------
parser = argparse.ArgumentParser()

parser.add_argument('--vendor', help="Vendor (optional)", 
    action='store', dest='vendor', default='')
parser.add_argument('--product', help='Product (required)', 
    action='store', required=True, dest='product')
parser.add_argument('--version', help='Version (required)', 
    action='store', required=True, dest='version')

args = parser.parse_args()


#------------------------------------------------------------------------------
# Processing
#------------------------------------------------------------------------------
info('Looking for "{vendor}{delim}{product} {version}" in cvedetails.com ' \
    'database...'.format(
        vendor  = args.vendor or '',
        delim   = ' ' if args.vendor else '',
        product = args.product,
        version = args.version))

resp = request_search(args.vendor, args.product, args.version)


#
# Case when there is not one exact match found
#
if 'List of cve security vulnerabilities related to this exact version' not in resp:

    # Check if searched version is present several times in the results
    version_found = False
    if 'No matches' not in resp:
        versions_results = parse_html_table_versions(resp)

        if args.version in versions_results:
            version_id = versions_results[args.version] # list of ids
            version = args.version
            success('Exact match found in the database (in {} entries, ' \
                'results will be merged)'.format(len(version_id)))
            vendor, vendor_id, product_id = get_ids_from_searchresults(resp, args)
            version_found = True

    # No exact match found
    if not version_found:
        warning('No exact match for this product/version. Checking for CVE in newer versions...')

        # Check if vendor+product is actually referenced in the database
        resp = request_search(args.vendor or '', args.product, '')

        if 'No matches' in resp:
            error('The product "{vendor}{delim}{product}" is not referenced in cvedetails.com database !'.format(
                vendor  = args.vendor or '',
                delim   = ' ' if args.vendor else '',
                product = args.product))
            sys.exit(1)

        # Check if there are referenced newer versions and take the closest one to the targeted version
        # Looping around targeted version till a newer version is found because cvedetails limits to 100 results 
        # per search. 
        # E.g. searching for "Nginx 0.8" will not work, for "Nginx" without version will only display the first 
        # 100 results which are versions older than 0.8, but searching for "Nginx 0.8%" will allow to find
        # newer version.
        i = len(args.version)
        superior_version_found = False
        while i >= 0:
            version_search = args.version[:i]+'%'
            info('Checking with version = {}'.format(version_search))
            resp = request_search(args.vendor or '', args.product, version_search)
            #print(resp)

            # If CVE results is directly displayed
            if 'Security Vulnerabilities' in resp:
                vendor, vendor_id, product_id, version, version_id = get_ids_from_cve_page(resp, args)

                try:
                    if LooseVersion(version) >= LooseVersion(args.version):
                        superior_version_found = True
                        break
                except:
                    pass

            # If table with matching versions displayed
            elif 'No matches' not in resp and 'Could not find any vulnerabilities' not in resp:
                # Need to handle several ids for a given version because cvedetails can have
                # several ids for different languages, editions, updates for a given version number
                versions_results = parse_html_table_versions(resp)
                
                version = get_closest_superior_version(args.version, versions_results.keys())
                version_id = versions_results[version] # list (may contain several ids)
                vendor, vendor_id, product_id = get_ids_from_searchresults(resp, args)

                if version:
                    superior_version_found = True
                    break
            i -= 1

        if not superior_version_found:
            error('No superior version found in cvedetails.com database')
            sys.exit(1)
        else:
            success('Closest superior version found in database is: {}'.format(version))
    
    


#
# Case when there is an exact match found in the database
# 
else:
    success('Exact match found in the database')

    # Retrieve Vendor & Vendor_id, Product id, Version id from the CVE
    # results page
    vendor, vendor_id, product_id, version, version_id = get_ids_from_cve_page(resp, args)

#
# Fetch CVE results
#
info('IDs summary: Vendor={vendor} [{vendor_id}] | Product={product} ' \
    '[{product_id}] | Version={version} [{version_id}]'.format(
        vendor     = vendor,
        vendor_id  = vendor_id,
        product    = args.product,
        product_id = product_id,
        version    = version,
        version_id = ','.join(version_id)))


jsons_list = list()
for v_id in version_id:
    info('Fetch results for version id {} ...'.format(v_id))
    r = requests.get(
        'http://www.cvedetails.com/json-feed.php?numrows=30&vendor_id={vendor_id}&' \
        'product_id={product_id}&version_id={version_id}&hasexp=0&opec=0&opov=0&opcsrf=0&' \
        'opfileinc=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&' \
        'opginf=0&opdos=0&orderby=3&cvssscoremin=0'.format(
            vendor_id  = vendor_id,
            product_id = product_id,
            version_id = v_id))

    if r.status_code != 200:
        error('HTTP Error occured. Code {} returned'.format(r.status_code))
    else:
        jsons_list.append(r.json())

if len(jsons_list) > 1:
    results = merge_jsons(jsons_list)
elif len(jsons_list) == 1:
    results = jsons_list[0]
else:
    error('No result fetched !')
    sys.exit(1)

#pprint.pprint(results)
if len(results) > 0:
    success('Total number of CVEs fetched: {}'.format(len(results)))
else:
    warning('No CVE found in database')
    sys.exit(1)


#
# Display CVE results
#
columns = [
    'ID',
    'CVSS',
    'Date',
    'Description',
    'URL',
    'Exploit?',
]
data = list()
for r in results:
    data.append([
        colorize(r['cve_id'], attrs='bold'),
        colorize(r['cvss_score'], color=color_cvss(r['cvss_score']), attrs='bold'),
        r['publish_date'],
        textwrap.fill(r['summary'], 80),
        r['url'],
        'None' if r['exploit_count'] == '0' else colorize(r['exploit_count'], color='red', attrs='bold'),
    ])

info('Results ordered by published date (desc):')
table(columns, data, hrules=True)