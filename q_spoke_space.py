#!/usr/bin/python3
import sys
import getopt
import getpass
import requests
import json
import time
import os
import keyring
import urllib.parse
import urllib3
urllib3.disable_warnings()
import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    sys.stderr.write("Usage: q_spoke_space.py [-hD] [-c user] [-s user] [-H user] [-u unit] spoke:path\n")
    sys.stderr.write("-h | --help : Prints Usage\n")
    sys.stderr.write("-D | --DEBUG : Generated debug output\n")
    sys.stderr.write("-c | --cred : Specify a common user on hub and spoke\n")
    sys.stderr.write("-s | --spoke_user : Specify a spoke user\n")
    sys.stderr.write("-H | --hub_user : Specify a hub user\n")
    sys.stderr.write("-u | --unit : Specify a unit [kb, mb, gb, tb, pb]\n")
    sys.stderr.write("spoke:path : Specify the name/IP of the spoke and the root of the spoke (colon separated)\n")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def oprint(fp, message):
    if fp:
        fp.write(message + '\n')
    else:
        print(message)
    return
def api_login(qumulo, user, password, token, node):
    in_keyring = True
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = input(node + " user: ")
        if not password:
            password = keyring.get_password(RING_SYSTEM, user)
        if not password:
            in_keyring = False
            password = getpass.getpass("Password: ")
        payload = {'username': user, 'password': password}
        payload = json.dumps(payload)
        autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
        dprint(str(autht.ok))
        auth = json.loads(autht.content.decode('utf-8'))
        dprint(str(auth))
        if autht.ok:
            auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
            if not in_keyring:
                use_ring = input("Put these credentials into keyring? [y/n]: ")
                if use_ring.startswith('y') or use_ring.startswith('Y'):
                    keyring.set_password(RING_SYSTEM, user, password)
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    dprint("AUTH_HEADERS: " + str(auth_headers))
    return(auth_headers)

def qumulo_get(addr, auth, api):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[GET]: retrying..")
            good = False
            time.sleep(5)
    if res.status_code == 200:
        dprint("RESULTS: " + str(res.content))
        results = json.loads(res.content.decode('utf-8'))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

def convert_from_bytes(bytes, unit):
    if unit == 'b':
        return(bytes, '')
    if unit == 'k':
        return(int(bytes/1000), unit)
    if unit == 'm':
        return(int(bytes/1000/1000), unit)
    if unit == 'g':
        return((int(bytes/1000/1000/1000), unit))
    if unit == 't':
        return(int(bytes/1000/1000/1000/1000), unit)
    if unit == 'p':
        return(int(bytes/1000/1000/1000/1000/1000), unit)
    sys.stderr.write("Unsupported unit: " + unit + ".  Supported: kb, mb, gb, tb, pb\n")
    exit(2)

if __name__ == "__main__":
    DEBUG = False
    timeout = 30
    token_file = ""
    token = ""
    user = ""
    password = ""
    hub_user = ""
    hub_password = ""
    qumulo = ""
    spoke = ""
    spoke_prefix = ""
    hub = ""
    hub_prefix = ""
    RING_SYSTEM = "q_spoke_space"
    unit = ""
    spoke_data = {}

    optlist, args = getopt.getopt(sys.argv[1:], 'hDu:c:s:H:', ['help', 'DEBUG', 'unit', 'cred', 'spoke_user', 'hub_user'])
    for opt, a in optlist:
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
        if opt in ('-u', '--unit'):
            unit = a[0].lower()
        if opt in ('-c', '--cred'):
            user = a
            hub_user = a
        if opt in ('-s', '--spoke_user'):
            spoke_user = a
        if opt in ('-H', '--hub_user'):
            hub_user = a
    try:
        qumulo = args.pop(0)
    except:
        usage()
    (spoke, spoke_path) = qumulo.split(':')
    if not spoke_path.endswith('/'):
        spoke_path = spoke_path + "/"
    spoke_auth = api_login(spoke, user, password, token, 'spoke')
    dprint("SPOKE_AUTH: " + str(spoke_auth))
    spokes = qumulo_get(spoke, spoke_auth, '/v1/portal/spokes/')
    dprint(str(spokes))
    for s in spokes['entries']:
        if s['spoke_root_path'] == spoke_path:
            spoke_data['id'] = s['id']
            spoke_data['uuid'] = s['hub_cluster_uuid']
            spoke_data['hub'] = s['hub_address']
            spoke_data['hub_id'] = s['hub_id']
    try:
        spoke_data['id']
    except:
        sys.stderr.write("Spoke " + qumulo + " is not found.\n")
        exit(2)
    dprint("SPOKE_DATA: " + str(spoke_data))
    hub_auth = api_login(spoke_data['hub'], hub_user, hub_password, token, 'hub')
    dprint("HUB_AUTH: " + str(hub_auth))
    hub_path_data = qumulo_get(spoke_data['hub'], hub_auth, '/v1/portal/hubs/' + str(spoke_data['hub_id']))
    hub_path_id_data = qumulo_get(spoke_data['hub'], hub_auth, '/v1/files/' +
                                  urllib.parse.quote(hub_path_data['root_path'], safe='') + '/info/attributes')
    hub_path_stats = qumulo_get(spoke_data['hub'], hub_auth, '/v1/files/' + str(hub_path_id_data['id']) + '/recursive-aggregates/')
    dprint("SIZE: " + str(hub_path_stats[0]['total_capacity']))
    hub_size = int(hub_path_stats[0]['total_capacity'])
    spoke_size_data = qumulo_get(spoke, spoke_auth, '/v1/portal/file-systems/')
    spoke_size = int(spoke_size_data[0]['usage_bytes'])
    percent_diff = spoke_size / hub_size
    if not unit:
        if hub_size >= 1000000000000000:
            (hub_size, hub_prefix) = convert_from_bytes(hub_size, 'p')
        elif hub_size >= 1000000000000:
            (hub_size, hub_prefix) = convert_from_bytes(hub_size, 't')
        elif hub_size >= 1000000000:
            (hub_size, hub_prefix) = convert_from_bytes(hub_size, 'g')
        elif hub_size > 1000000:
            (hub_size, hub_prefix) = convert_from_bytes(hub_size, 'm')
        elif hub_size > 1000:
            (hub_size, hub_prefix) = convert_from_bytes(hub_size, 'k')
        if spoke_size >= 1000000000000000:
            (spoke_size, spoke_prefix) = convert_from_bytes(spoke_size, 'p')
        elif spoke_size >= 1000000000000:
            (spoke_size, spoke_prefix) = convert_from_bytes(spoke_size, 't')
        elif spoke_size >= 1000000000:
            (spoke_size, spoke_prefix) = convert_from_bytes(spoke_size, 'g')
        elif spoke_size > 1000000:
            (spoke_size, spoke_prefix) = convert_from_bytes(spoke_size, 'm')
        elif spoke_size > 1000:
            (spoke_size, spoke_prefix) = convert_from_bytes(spoke_size, 'k')
    else:
        (hub_size, hub_prefix) = convert_from_bytes(hub_size, unit)
        (spoke_size, spoke_prefix) = convert_from_bytes(spoke_size, unit)
    print("Hub: " + str(hub_size) + " " + hub_prefix + "b")
    print("Spoke: " + str(spoke_size) + " " + spoke_prefix + "b : ", end='')
    print ('{:1.1f}%'.format(percent_diff))



