#!/usr/bin/env python3
import subprocess
import ipaddress
import sys
import xmltodict
import json
import os
import socket
from functools import reduce

target_host = None
target_ip = None
no_cache = False
use_nmap_pn = False

hosts_file_path = '/etc/hosts'
script_dir = os.path.dirname(os.path.abspath(__file__))

subdomain_wordlist_small = os.path.join(script_dir, 'wordlists/subdomains-small.txt')
fuff_dummy_wordlist = os.path.join(script_dir, 'wordlists/dummy-test.txt')

data_path = lambda x: os.path.join(script_dir, f"data/{x}")
nmap_initial_scan_path = lambda x: os.path.join(script_dir, f"data/{x}/nmap_report.xml")
ffuf_report_path = lambda x: os.path.join(script_dir, f"data/{x}/ffuf_scan.json")

allowed_ports_for_subdomain_enum = [80, 443, 5000]

true_false = [True, False]
# possible_codes = ['', '200', '403', '500', '401', '301', '302', '200,301', '301,302', '200,302', '200,301,302']
possible_codes = ['', '200', '403', '301']
disallowed_sizes = []

subdomain_enum_args = [(x, y, '') for x in true_false for y in possible_codes]


def run_subdomain_enum_scan(target_host, args, wordlist):
    [use_https, codes, size] = args
    protocol = "https" if use_https == True else "http"
    codes_string = f"-fc {codes}" if len(codes) > 0 else ""
    size_string = f"-fs {size}" if size else ""
    command = f"ffuf -u {protocol}://{target_host} -w {wordlist} -H \"Host: FUZZ.{target_host}\" {codes_string} {size_string} -o {ffuf_report_path(target_host)}"
    # print(f"Running: {command}")

    try:
        subprocess.run(command, check=True, shell=True, timeout=24, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None

    with open(ffuf_report_path(target_host), 'r') as file:
        scan = file.read()
        data = json.loads(scan)
        return data

def run_nmap_scan(target_host):
    global no_cache
    global use_nmap_pn

    if not os.path.exists(nmap_initial_scan_path(target_host)) or no_cache == True:
        command = []
        if use_nmap_pn:
            command = ['nmap', '-sT', '-T4', '-p-', '-Pn', '-oX', nmap_initial_scan_path(target_host), target_host]
        else:
            command = ['nmap', '-sT', '-T4', '-p-', '-oX', nmap_initial_scan_path(target_host), target_host]

        print(f"nmap scan starting on {target_host}")
        subprocess.run(command, check=True) #, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print("Target scanned previously, skipping.")

    return parse_nmap_xml(nmap_initial_scan_path(target_host))

def parse_nmap_xml(file_path):
    with open(file_path, 'r') as file:
        xml_string = file.read()
    parsed_dict = xmltodict.parse(xml_string)

    host_status = 'down'
    open_ports = []
    os_info = { "matches": []}

    scan_status = parsed_dict['nmaprun']['runstats']['finished']['@exit']

    host = parsed_dict['nmaprun']['host']
    
    if host['status']['@state'] == 'up':
        host_status = 'up'
        if isinstance(host['ports']['port'], list):
            for port in host['ports']['port']:
                port_state = port['state']
                if port_state['@state'] == 'open':
                    port_number = port['@portid']
                    service_name = port['service']['@name'] if 'service' in port else 'unknown'
                    open_ports.append({ 'port_number': port_number, 'service_name': service_name })
        else:
            port = host['ports']['port']
            port_state = port['state']
            if port_state['@state'] == 'open':
                port_number = port['@portid']
                service_name = port['service']['@name'] if 'service' in port else 'unknown'
                open_ports.append({ 'port_number': port_number, 'service_name': service_name })
        
    
    if 'os' in host:
        host_os = host['os']
        os_matches = host_os['osmatch']

        if isinstance(os_matches, list):
            for match in os_matches:
                os_info['matches'].append({
                    "name": match['@name'],
                    "accuracy": match['@accuracy']
                })
        else:
            os_info['matches'].append({
                "name": os_matches['@name'],
                "accuracy": os_matches['@accuracy']
            })

    return {
        'host_status': host_status, 
        'open_ports': open_ports, 
        'scan_status': scan_status, 
        'os_info': os_info 
    }

def setup():
    global target_host

    if not os.path.exists(data_path(target_host)):
        os.makedirs(data_path(target_host))

def parse_arguments():
    global no_cache
    global target_host
    global target_ip

    if len(sys.argv) < 2:
        print("provide a target")
        exit(1)

    if len(sys.argv) < 3:
        print("provide a ip")
        exit(1)

    target_host = sys.argv[1]
    target_ip = sys.argv[2]
    args = sys.argv[3:]

    if any(x == '--no-cache' for x in args):
        no_cache = True

    if any(x == '--use-nmap-Pn' for x in args):
        use_nmap_pn = True

def host_file_entry_exists(host):
    with open(hosts_file_path, 'r') as file:
        lines = file.readlines()

    return any(host in line.strip() for line in lines)

def hosts_file_new_entry():
    with open(hosts_file_path, 'a') as file:
        file.write(f'\n# Entry created from web_scan script\n')

def add_to_hosts(ip, host):
    if not host_file_entry_exists(host):
        with open(hosts_file_path, 'a') as file:
            file.write(f'{ip} {host}\n')
            print(f'Added {ip} {host} to {hosts_file_path}')
    else:
        print(f'{host} already exists in {hosts_file_path}')


def main():
    global disallowed_sizes
    global target_host
    global target_ip

    parse_arguments()
    setup()    

    if not host_file_entry_exists(target_host):
        hosts_file_new_entry()

    add_to_hosts(target_ip, target_host)

    print("\n*******************************************")
    print(f"Scanning with nmap {target_host}")
    report = run_nmap_scan(target_host)

    print(f"[{report['scan_status']}] Scan finished\n")

    print("\n*******************************************")
    print(f"Host Status: {report['host_status']}")

    if len(report['os_info']['matches']) > 0:
        print("OS Detection:")
        for match in report['os_info']['matches']:
            print(f"{match['name']}: {match['accuracy']}%")

    print("\n*******************************************")
    print("Open Ports:")
    for port in report['open_ports']:
        print(f"\n[Port]    {port['port_number']}")
        print(f"[Service] {port['service_name']}")

    print("\n*******************************************")
    print("Subdomain scanning...")

    print("\nPreliminary scan ", end="", flush=True)
    preliminary_subdomain_scan_results = []
    for args in subdomain_enum_args:
        tmp_result = run_subdomain_enum_scan(target_host, args, fuff_dummy_wordlist)
        if tmp_result == None:
            print('x', end="", flush=True)
        else: 
            # if the dummy-test triggered results, the configuration is invalid
            if len(tmp_result['results']) < 1:
                print('+', end="", flush=True)
                preliminary_subdomain_scan_results.append([tmp_result, args])
            else:
                print('-', end="", flush=True)
                results = tmp_result['results']
                sizes = {}

                for result in results:
                    length = result['length']
                    if length in sizes:
                        sizes[length] = sizes[length] + 1
                    else:
                        sizes[length] = 1
                
                for key, value in sizes.items():
                    if (value > 3 and not any(x == key for x in disallowed_sizes)): 
                        disallowed_sizes.append(key)
        
    print(f"\n{len(preliminary_subdomain_scan_results)} preliminary subdomain fuzz configurations are favorable\n")

    print("Running main scans ", end="", flush=True)
    augmented_scan_configurations = [x[1] for x in preliminary_subdomain_scan_results]
    if len(disallowed_sizes) > 0:
        for size in disallowed_sizes:
            augmented_scan_configurations.insert(0, (False, '', size))
            augmented_scan_configurations.insert(0, (True, '', size))

    # print(f"configuration {augmented_scan_configurations}")
    subdomain_scan_results = []
    for potentially_good_configuration in augmented_scan_configurations:
        result = run_subdomain_enum_scan(target_host, potentially_good_configuration, subdomain_wordlist_small)
        if result == None:
            print('x', end="", flush=True)
        else:
            subdomain_scan_results.append(result)
            if len(result['results']) > 0:
                print('+', end="", flush=True)
            else:
                print('-', end="", flush=True)

    all_hosts_results = [] 
    for scan_result in subdomain_scan_results:
        if len(scan_result['results']) > 0:
            for result in scan_result['results']:
                all_hosts_results.append((result['host'], result['url'], result['status']))

    print(f"\nSubdomain enumeration results:\n")
    if len(all_hosts_results) > 0:
        for result in list(set(all_hosts_results)):
            print(f"[Subdomain] ({result[2]}) ({result[1]})   {result[0]}")

        print(f"\nAdding entries to /etc/hosts")
        for result in list(set(all_hosts_results)):
            add_to_hosts(target_ip, result[0])
    else:
        print("No subdomain found.")

if __name__ == '__main__':
    main()
