#!/usr/bin/env python3
#
# Copyright 2019 Trend Micro and contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function
from tokenize import group

import xlsxwriter
import argparse
import os
import sys


from smartcheck import Smartcheck

ALL_SEVERITIES = [
    'defcon1',
    'critical',
    'high',
    'medium',
    'low',
    'negligible',
    'unknown',
]


def get_vector(vector, vulnerability):
    """Get a vector out of the CVSS definition (if present) for a vulnerability."""

    vectors = []

    # Some sources have metadata as { metadata: NVD: CVSSv3: Vectors: "..." }
    # and others have { metadata: CVSSv2: "..." }
    if 'metadata' in vulnerability:
        if 'NVD' in vulnerability['metadata']:
            vectors = vulnerability['metadata']['NVD'].get(
                'CVSSv3', {}).get('Vectors', '').split('/')
            if len(vectors) == 1:
                vectors = vulnerability['metadata']['NVD'].get(
                    'CVSSv2', {}).get('Vectors', '').split('/')
        else:
            cvssV2 = vulnerability['metadata'].get('CVSSv2', None)
            if isinstance(cvssV2, str):
                vectors = cvssV2.split('/')
                # The first element is the score, which we're not using here
                vectors.pop(0)

    found = list(filter(lambda x: vector in x, vectors))
    if found:
        return found[0]

    return None


def sev_list(min_level):
    return ALL_SEVERITIES[:ALL_SEVERITIES.index(min_level) + 1]


def parse_args():
    """Parse command-line arguments."""

    # This is split out from the main() function solely so that I can skip over
    # it more easily when going through the code.

    parser = argparse.ArgumentParser(
        description='List vulnerabilities found in scans',
    )

    parser.add_argument(
        '--smartcheck-host',
        action='store',
        default=os.environ.get('DSSC_SMARTCHECK_HOST', None),
        help='The hostname of the Deep Security Smart Check deployment. Example: smartcheck.example.com'
    )

    parser.add_argument(
        '--smartcheck-user',
        action='store',
        default=os.environ.get('DSSC_SMARTCHECK_USER', None),
        help='The userid for connecting to Deep Security Smart Check'
    )

    parser.add_argument(
        '--smartcheck-password',
        action='store',
        default=os.environ.get('DSSC_SMARTCHECK_PASSWORD', None),
        help='The password for connecting to Deep Security Smart Check'
    )

    parser.add_argument(
        '--insecure-skip-tls-verify',
        action='store_true',
        default=os.environ.get('DSSC_INSECURE_SKIP_TLS_VERIFY', False),
        help='Ignore certificate errors when connecting to Deep Security Smart Check'
    )

    parser.add_argument(
        '--min-severity',
        action='store',
        default='high',
        help='The minimum severity of vulnerability to show. Defaults to "high". Values: [defcon1,critical,high,medium,low,negligible,unknown]'
    )

    parser.add_argument(
        '--show-overridden',
        action='store_true',
        help='Show vulnerabilities that have been marked as overridden'
    )

    parser.add_argument(
        '--show-fixed',
        action='store_true',
        help='Show vulnerabilities that have been fixed by a later layer'
    )

    parser.add_argument(
        'image',
        help='The image to scan. Example: registry.example.com/project/image:latest'
    )

    return parser.parse_args()


def generate_xls(data):

    import xlsxwriter

    workbook = xlsxwriter.Workbook('/root/app/DSSCReport.xlsx')

    # By default worksheet names in the spreadsheet will be
    # Sheet1, Sheet2 etc., but we can also specify a name.

    worksheet = workbook.add_worksheet("Security Analysis")

    # Start from the first cell. Rows and
    # columns are zero indexed.

    header = workbook.add_format(
        {'bold': True, 'bg_color': '#F7F9FA', 'border': 1, 'font': 'Century Gothic', 'font_size': 20,
         'font_color': '#666A6D'})
    header.set_align('center')

    error = workbook.add_format(
        {'bold': True, 'bg_color': '#F40A0A', 'border': 1, 'font': 'Century Gothic', 'font_size': 20,
         'font_color': '#FAFAF8'})
    error.set_align('center')

    subhead = workbook.add_format(
        {'bold': True, 'bg_color': '#1E5C9B', 'font': 'Century Gothic', 'font_size': 12, 'font_color': '#F8FAFC'})

    tablehead = workbook.add_format(
        {'bold': True, 'bg_color': '#10384C', 'font': 'Century Gothic', 'font_size': 10, 'font_color': '#F8FAFC'})

    # Populating malware report tableno1

    worksheet.merge_range(0, 0, 2, 6, data['malware']['name'], header)

    worksheet.set_column('A:D', 25)

    col = 0
    row = 3

    row += 2  # row=4 , excelrow=5

    malwarelen = len(data['malware']['items'])
    size = "A{}:B{}".format(row, malwarelen + 5)

    if data['malware']['items']:
        no_of_columns = data['malware']['items'][0].keys()
        heads = list(no_of_columns)
        worksheet.add_table(size, {'columns': [{'header': heads[0], 'header_format': tablehead},
                                               {'header': heads[1], 'header_format': tablehead}
                                               ]})

        for item in data['malware']['items']:
            worksheet.write(row, col, item['name'])
            worksheet.write(row, col + 1, item['infected_file'])
            row += 1
    else:
        message = "No-Record Found"
        worksheet.merge_range(row + 2, col, row + 4, col + 6, message,
                              error)
        row += 4
    # row=5 , excelrow=6

    tablesize = row + 5  # tablesize=12 , excelrow=8

    # Populating content risk  tableno2

    tablesize2 = tablesize  # row=8 excelrow=9

    # worksheet = workbook.add_worksheet('content_risk')
    worksheet.set_column('A:D', 25)
    worksheet.merge_range(tablesize2, col, tablesize2 + 2, col + 6, data['content_risk']['name'], header)

    tablesize2 += 5  # excelrow=17 tablesize2=16

    contentlen = len(data['content_risk']['items'])
    size2 = "A{}:C{}".format(tablesize2, contentlen + tablesize2 + 1)

    if data['content_risk']['items']:
        no_of_columns2 = data['content_risk']['items'][0].keys()
        heads2 = list(no_of_columns2)
        worksheet.add_table(size2, {'columns': [{'header': heads2[0], 'header_format': tablehead},
                                                {'header': heads2[1], 'header_format': tablehead},
                                                {'header': heads2[2], 'header_format': tablehead}
                                                ]})

        for item in data['content_risk']['items']:
            worksheet.write(tablesize2, col, item[heads2[0]])
            worksheet.write(tablesize2, col + 1, item[heads2[1]])
            worksheet.write(tablesize2, col + 2, item[heads2[2]])
            tablesize2 += 1
    else:
        message = "No-Record"
        worksheet.merge_range(tablesize2 + 2, col, tablesize2 + 4, col + 6, message,
                              error)
        tablesize2 += 4

    tablesize3 = tablesize2 + 5

    # Populating compliance_check_failures report tableno3

    # tablesize3 = 0

    # worksheet = workbook.add_worksheet('compliance_check_failures')
    worksheet.set_column('A:D', 25)
    worksheet.merge_range(tablesize3, col, tablesize3 + 2, col + 6, data['compliance_check_failures']['name'],
                          header)
    tablesize3 += 2

    compliancelen = len(data['compliance_check_failures']['items'])
    size3 = "A{}:C{}".format(tablesize3, compliancelen + tablesize3 + 1)

    if data['compliance_check_failures']['items']:
        no_of_columns3 = data['compliance_check_failures']['items'][0].keys()
        heads3 = list(no_of_columns3)
        worksheet.add_table(size3, {'columns': [{'header': heads3[0], 'header_format': tablehead},
                                                {'header': heads3[1], 'header_format': tablehead},
                                                {'header': heads3[2], 'header_format': tablehead}
                                                ]})
        for item in data['compliance_check_failures']['items']:
            worksheet.write(tablesize3, col, item[heads3[0]])
            worksheet.write(tablesize3, col + 1, item[heads3[1]])
            worksheet.write(tablesize3, col + 2, item[heads3[2]])

            tablesize3 += 1

    else:
        message = "No-Record Found"
        worksheet.merge_range(tablesize3 + 2, col, tablesize3 + 4, col + 6, message,
                              error)
        tablesize3 += 4

    tablesize4 = tablesize3 + 5

    # Populating compliance_checklist report tableno4

    # tablesize4 = 0

    # worksheet = workbook.add_worksheet('compliance_checklist')
    # worksheet.set_column('A:D', 25)
    worksheet.merge_range(tablesize4, col, tablesize4 + 2, col + 6, data['compliance_checklist']['name'], header)

    tablesize4 += 2

    worksheet.merge_range(tablesize4 + 2, col, tablesize4 + 2, col + 1,
                          data['compliance_checklist']['pci-dss']['name'],
                          subhead)

    tablesize4 += 4  # excelrow=17 tablesize2=16

    checklistlen = len(data['compliance_checklist']['pci-dss']['items'])
    size4 = "A{}:B{}".format(tablesize4, checklistlen + tablesize4 + 1)

    if data['compliance_checklist']['pci-dss']['items']:
        no_of_columns4 = data['compliance_checklist']['pci-dss']['items'][0].keys()
        heads4 = list(no_of_columns4)
        worksheet.add_table(size4, {'columns': [{'header': heads4[0], 'header_format': tablehead},
                                                {'header': heads4[1], 'header_format': tablehead}
                                                ]})

        for item in data['compliance_checklist']['pci-dss']['items']:
            worksheet.write(tablesize4, col, item['result_title'])
            worksheet.write(tablesize4, col + 1, item['result'])
            tablesize4 += 1
    else:
        message = "No-Record Found"
        worksheet.merge_range(tablesize4 + 2, col, tablesize4 + 4, col + 6, message,
                              error)
        tablesize4 += 4

    tablesize5 = tablesize4 + 5

    # Populating compliance_checklist report tableno5

    worksheet.merge_range(tablesize5, col, tablesize5, col + 1,
                          data['compliance_checklist']['nist800190']['name'],
                          subhead)

    tablesize5 += 2

    checklistlen2 = len(data['compliance_checklist']['nist800190']['items'])
    size5 = "A{}:B{}".format(tablesize5, checklistlen2 + tablesize5)

    if data['compliance_checklist']['nist800190']['items']:
        no_of_columns5 = data['compliance_checklist']['nist800190']['items'][0].keys()
        heads5 = list(no_of_columns5)
        worksheet.add_table(size5, {'columns': [{'header': heads5[0], 'header_format': tablehead},
                                                {'header': heads5[1], 'header_format': tablehead}
                                                ]})

        for item in data['compliance_checklist']['nist800190']['items']:
            worksheet.write(tablesize5, col, item['result_title'])
            worksheet.write(tablesize5, col + 1, item['result'])
            tablesize5 += 1
    else:
        message = "No-Record Found"
        worksheet.merge_range(tablesize5 + 2, col, tablesize5 + 4, col + 6, message,
                              error)
        tablesize5 += 4

    tablesize6 = tablesize5 + 4

    # Populating compliance_checklist report tableno6

    worksheet.merge_range(tablesize6, col, tablesize6, col + 1, data['compliance_checklist']['hipaa']['name'],
                          subhead)

    tablesize6 += 2

    checklistlen3 = len(data['compliance_checklist']['hipaa']['items'])
    size6 = "A{}:B{}".format(tablesize6, checklistlen3 + tablesize6)

    if data['compliance_checklist']['hipaa']['items']:
        no_of_columns6 = data['compliance_checklist']['hipaa']['items'][0].keys()
        heads6 = list(no_of_columns6)
        worksheet.add_table(size6, {'columns': [{'header': heads6[0], 'header_format': tablehead},
                                                {'header': heads6[1], 'header_format': tablehead}
                                                ]})

        for item in data['compliance_checklist']['hipaa']['items']:
            worksheet.write(tablesize6, col, item['result_title'])
            worksheet.write(tablesize6, col + 1, item['result'])
            tablesize6 += 1
    else:
        message = "No-Record Found"
        worksheet.merge_range(tablesize6 + 2, col, tablesize6 + 4, col + 6, message,
                              error)
        tablesize6 += 4

    tablesize7 = tablesize6 + 5

    # Populating vulnerable_package report tableno7

    # tablesize7 = 0

    # worksheet = workbook.add_worksheet('vulnerable_package')
    # worksheet.set_column('A:D', 25)
    worksheet.set_column('E:E', 57)
    worksheet.merge_range(tablesize7, col, tablesize7 + 2, col + 6, data['vulnerable_package']['name'], header)

    tablesize7 += 5

    vulnerablelen = len(data['vulnerable_package']['items'])
    size7 = "A{}:E{}".format(tablesize7, vulnerablelen + tablesize7)

    if data['vulnerable_package']['items']:
        no_of_columns7 = data['vulnerable_package']['items'][0].keys()
        heads7 = list(no_of_columns7)
        worksheet.add_table(size7, {'columns': [{'header': heads7[0], 'header_format': tablehead},
                                                {'header': heads7[1], 'header_format': tablehead},
                                                {'header': heads7[2], 'header_format': tablehead},
                                                {'header': heads7[3], 'header_format': tablehead},
                                                {'header': heads7[4], 'header_format': tablehead}
                                                ]})

        for item in data['vulnerable_package']['items']:
            worksheet.write(tablesize7, col, item['name'])
            worksheet.write(tablesize7, col + 1, item['severity'])
            worksheet.write(tablesize7, col + 2, item['venerability'])
            worksheet.write(tablesize7, col + 3, item['vector'])
            worksheet.write(tablesize7, col + 4, item['link'])
            tablesize7 += 1
    else:
        message = "No-Record Found"
        worksheet.merge_range(tablesize7 + 2, col, tablesize7 + 4, col + 6, message,
                              error)
        tablesize7 += 4

    workbook.close()



def get_analysis(smartcheck_host, smartcheck_user, smartcheck_password, min_severity, image, show_fixed,
                 show_overridden,
                 insecure_skip_tls_verify=True):
    result = {
        "malware": {
            "name": "Malware found in image",
            "items": []
        },
        "content_risk": {
            "name": "Content secret risk found",
            "items": []
        },
        "compliance_check_failures": {
            "name": "Failed Compliance checklist for image",
            "items": []
        },
        "compliance_checklist": {
            "name": "Display Checklist_compliance of Trend Micro",
            "pci-dss": {
                "name": "Trend Micro PCI-DSS v3 Docker Compliance",
                "items": []
            },
            "nist800190": {
                "name": "Trend Micro NIST 800-190 Docker Compliance",
                "items": []
            },
            "hipaa": {
                "name": "Trend Micro HIPAA Docker Compliance",
                "items": []
            }

        },
        "vulnerable_package": {
            "name": "vulnerable_package list table",
            "items": []

        }
    }

    if smartcheck_host is None:
        print('smartcheck-host is required', file=sys.stderr)
        sys.exit(1)

    try:
        notable_list = sev_list(min_severity)
    except ValueError:
        print('unrecognized severity')
        sys.exit(1)

    with Smartcheck(
            base=smartcheck_host,
            verify=(not insecure_skip_tls_verify),
            user=smartcheck_user,
            password=smartcheck_password
    ) as session:
        # list_scans(image) will return a generator that will give us all of the
        # scans for that image if we ask for them. We're only going to ask for one
        # because we only care about the last scan result.

        for scan in session.list_scans(image, limit=1):

            # We only want to print out the header if there are notable vulnerabilities,
            # which we won't know until later.
            first = True

            # list_vulnerable_packages(scan) will return a generator that will give
            # us all of the vulnerable packages. Each package will have a list of
            # vulnerabilities.

            for package_malware in session.list_malware(scan):
                result['malware']['items'].append({
                    "name": package_malware['icrc']['name'],
                    "infected_file": package_malware['filename']
                })
            for package_content in session.list_content_findings(scan):
                result['content_risk']['items'].append({
                    "severity": package_content['severity'],
                    "severity content found in image": package_content['metadata']['SubCategory1'],
                    "found at": package_content['filename'],
                })

            for package_checklist in session.list_checklist_findings(scan):
                if package_checklist['profile']['title'] == "Trend Micro PCI-DSS v3 Docker Compliance":
                    result['compliance_checklist']['pci-dss']["items"].append({
                        "result_title": package_checklist['result']['title'],
                        "result": package_checklist['result']['result']})

            for package_checklist in session.list_checklist_findings(scan):
                if package_checklist['profile']['title'] == "Trend Micro NIST 800-190 Docker Compliance":
                    result['compliance_checklist']['nist800190']['items'].append({
                        "result_title": package_checklist['result']['title'],
                        "result": package_checklist['result']['result']})
            for package_checklist in session.list_checklist_findings(scan):
                if package_checklist['profile']['title'] == "Trend Micro HIPAA Docker Compliance":
                    result['compliance_checklist']['hipaa']['items'].append({
                        "result_title": package_checklist['result']['title'],
                        "result": package_checklist['result']['result']})

            for package in session.list_vulnerable_packages(scan):
                name = package.get('name', "-unknown-")

                # Now let's go through the vulnerabilities.
                for vulnerability in package['vulnerabilities']:
                    severity = vulnerability['severity']

                    # Skip low-severity vulnerabilities unless the user wants them
                    if not severity in notable_list:
                        continue

                    # Don't show vulnerabilities that have been fixed
                    if 'fixed' in vulnerability:
                        if not show_fixed:
                            continue

                    # Only show overridden vulnerabilities if the user has asked for them
                    if 'override' in vulnerability:
                        if not show_overridden:
                            continue

                    cve = vulnerability['name']
                    link = vulnerability['link']
                    vector = get_vector('AV:', vulnerability)
                    if vector is not None:
                        # Some sources encode the full vector (for example AV:NETWORK),
                        # others use the abbreviation (AV:N). We'll abbreviate for
                        # consistency.
                        vector = vector[:4]
                    else:
                        vector = '?'

                    # We have a notable vulnerability that we want to display, if
                    # it's the first one we'll add a pretty header
                    if first:
                        first = False

                    result['vulnerable_package']['items'].append({
                        "name": name,
                        "severity": severity,
                        "venerability": cve,
                        "vector": vector,
                        "link": link
                    })

            break

    return result


def main():
    """
    Mainline
    """
    args = parse_args()

    result = get_analysis(args.smartcheck_host, args.smartcheck_user, args.smartcheck_password, args.min_severity,
                          args.image, args.show_fixed,
                          args.show_overridden)
    print(result)
    print("vulnerable result  ", result['vulnerable_package']['items'])
    generate_xls(result)
    


if __name__ == '__main__':
    main()
