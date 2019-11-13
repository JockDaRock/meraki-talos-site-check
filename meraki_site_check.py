import requests
import time
from openpyxl import Workbook, load_workbook
import ipaddress
import re
import datetime

def is_ip_or_hostname(host_ip):
    re_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ip = re.findall(re_ip, host_ip)
    if len(ip) == 0:
        return "hostname"
    else:
        return "ip"


def is_private_ip(ip_addy):
    priv_ip = ipaddress.ip_address(ip_addy).is_private
    return priv_ip

def talos_blacklist_check(host):
    blacklist_check_url = "https://talosintelligence.com/sb_api/blacklist_lookup"

    talos_headers = {
        "Accept": "*/*",
        "Referer": "https://talosintelligence.com/reputation_center/lookup?search={0}".format(host),
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36"
        }

    talos_params = {"query_type": "domain", "query_entry": host}

    talos_req = requests.get(blacklist_check_url, params=talos_params, headers=talos_headers)

    print(talos_req.text)

    blacklist_check = talos_req.json()

    blacklist_status = blacklist_check["entry"]["status"]

    if blacklist_status == "ACTIVE":
        print(talos_req.text)

    return blacklist_check

def meraki_network_traffic(net_ID, api_key, time_span, xl_sheet):

    url = "https://api.meraki.com/api/v0/networks/{0}/traffic".format(net_ID)

    querystring = {"timespan": time_span}

    headers = {
        'Accept': "*/*",
        'X-Cisco-Meraki-API-Key': api_key,
        }

    response = requests.request("GET", url, headers=headers, params=querystring)
    
    site_json = response.json()
    count = 2

    for i in site_json:
        meraki_dest = i["destination"]
        app = i["application"]
        protocol = i["protocol"]
        dest_port = i["port"]
        kilo_bytes_recv = i["recv"]
        kilo_bytes_sent = i["sent"]
        num_flows = i["flows"]
        active_time = i["activeTime"]
        num_client = i["numClients"]
        print(meraki_dest)

        if meraki_dest == None:
            print("Destination is null, application type {0}.".format(app))
        else:
            if is_ip_or_hostname(meraki_dest) == "hostname":
                active_blacklist = talos_blacklist_check(meraki_dest)
                active_inactive = active_blacklist["entry"]["status"]
                
                if active_inactive != "NOT_FOUND":
                    print(meraki_dest)
                    try:
                        first_seen = str(active_blacklist["entry"]["first_seen"])
                    except:
                        first_seen = ""
                    try:
                        expiration = str(active_blacklist["entry"]["expiration"])
                    except:
                        expiration = ""
                    xl_sheet["A{0}".format(str(count))] = meraki_dest
                    xl_sheet["C{0}".format(str(count))] = str(active_blacklist["entry"]["classifications"])
                    xl_sheet["D{0}".format(str(count))] = first_seen
                    xl_sheet["E{0}".format(str(count))] = expiration
                    xl_sheet["F{0}".format(str(count))] = str(active_blacklist["entry"]["status"])
                    xl_sheet["G{0}".format(str(count))] = protocol
                    xl_sheet["H{0}".format(str(count))] = dest_port
                    xl_sheet["I{0}".format(str(count))] = kilo_bytes_recv
                    xl_sheet["J{0}".format(str(count))] = kilo_bytes_sent
                    xl_sheet["K{0}".format(str(count))] = num_flows
                    xl_sheet["L{0}".format(str(count))] = num_client
                    xl_sheet["M{0}".format(str(count))] = active_time

                    if active_inactive == "ACTIVE":
                        xl_sheet["B{0}".format(str(count))] = "ACTIVE_BLACKLIST"
                    else:
                        xl_sheet["B{0}".format(str(count))] = "INACTIVE_BLACKLIST"

                    count = count + 1

            elif is_private_ip(meraki_dest):
                print("Meraki destination {0} is a private address and will not be checked.".format(meraki_dest))
            else:
                active_blacklist = talos_blacklist_check(meraki_dest)
                active_inactive = active_blacklist["entry"]["status"]
                
                if active_inactive != "NOT_FOUND":
                    print(meraki_dest)
                    try:
                        first_seen = str(active_blacklist["entry"]["first_seen"])
                    except:
                        first_seen = ""
                    try:
                        expiration = str(active_blacklist["entry"]["expiration"])
                    except:
                        expiration = ""
                    xl_sheet["A{0}".format(str(count))] = meraki_dest
                    xl_sheet["C{0}".format(str(count))] = str(active_blacklist["entry"]["classifications"])
                    xl_sheet["D{0}".format(str(count))] = first_seen
                    xl_sheet["E{0}".format(str(count))] = expiration
                    xl_sheet["F{0}".format(str(count))] = str(active_blacklist["entry"]["status"])
                    xl_sheet["G{0}".format(str(count))] = protocol
                    xl_sheet["H{0}".format(str(count))] = dest_port
                    xl_sheet["I{0}".format(str(count))] = kilo_bytes_recv
                    xl_sheet["J{0}".format(str(count))] = kilo_bytes_sent
                    xl_sheet["K{0}".format(str(count))] = num_flows
                    xl_sheet["L{0}".format(str(count))] = num_client
                    xl_sheet["M{0}".format(str(count))] = active_time

                    if active_inactive == "ACTIVE":
                        xl_sheet["B{0}".format(str(count))] = "ACTIVE_BLACKLIST"
                    else:
                        xl_sheet["B{0}".format(str(count))] = "INACTIVE_BLACKLIST"

                    count = count + 1
            
            #Talos throttles requests, so some requests will fail if you don't slow down.
            time.sleep(0.5)
    
    return "All Done!!!"


if __name__ == "__main__":
    # Enter your Meraki Org ID and assoicated Meraki API key to use this application

    netID = "<your-meraki-network-id>"
    apiKey = "<your-meraki-api-key>"
    #timespan = "2592000"
    #timespan = "86400"
    timespan = "7200"

    header_row = {"A1": "Destination", "B1": "Active / InActive Blacklist", "C1": "Blacklist Type", "D1": "First Seen", "E1": "Expiration Date", "F1": "Blacklist Status", "G1": "Protocol to Dest", "H1": "Dest Port", "I1": "KB Recv", "J1": "KB Sent", "K1": "Packet Flows", "L1": "Meraki Clients", "M1": "Time Active Milliseconds"}
    
    workbook = Workbook()
    sheet = workbook.active

    sheet["A1"] = header_row["A1"]
    sheet["B1"] = header_row["B1"]
    sheet["C1"] = header_row["C1"]
    sheet["D1"] = header_row["D1"]
    sheet["E1"] = header_row["E1"]
    sheet["F1"] = header_row["F1"]
    sheet["G1"] = header_row["G1"]
    sheet["H1"] = header_row["H1"]
    sheet["I1"] = header_row["I1"]
    sheet["J1"] = header_row["J1"]
    sheet["K1"] = header_row["K1"]
    sheet["L1"] = header_row["L1"]
    sheet["M1"] = header_row["M1"]

    print(meraki_network_traffic(netID, apiKey, timespan, sheet))
    workbook.save(filename="dest_talos_blacklist_check_{0}.xlsx".format(datetime.datetime.isoformat(datetime.datetime.now())))

