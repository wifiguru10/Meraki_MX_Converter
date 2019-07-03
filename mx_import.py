#!/usr/bin/python3 -i

import csv
from datetime import datetime
import getopt
import logging
import os,sys
import time
import ipaddress
from meraki.meraki_client import MerakiClient
from meraki.models.rule_model import RuleModel
from meraki.models.update_network_l3_firewall_rules_model import UpdateNetworkL3FirewallRulesModel
from meraki.exceptions.api_exception import APIException
from ciscoconfparse import CiscoConfParse

import asa_to_mx

SYSLOG_ENABLED = False


class Meraki_org:
    api=""
    org=""
    net=""
    api_client = ""
    ruleFile = ""
    vlans = []
    iface = []
    subnets = []
    
    #old interfaces imported from config
    network_interfaces = {}
    #has interface table for NEW/TARGET network (uses these interfaces to re-map)
    target_interfaces={}
    #folloing holds SOURCE:TARGET values for IP's and subnets
    mapping_table = {} 


    def __init__(self):
        self.api= ""
        self.org= ""
        self.net= ""
        self.api_client = ""

    def set(self,a,o,n):
        self.api= a
        self.org= o
        self.net= n
        self.api_client = MerakiClient(a)


    def setRuleFile(self,rule_file):
        self.ruleFile(rule_file)


#ruleFile=''

#vlans=[]
#iface=[]
#subnets=[]


def loadInputFile(rFile):
    input_file=open(rFile)
    csv_reader = csv.reader(input_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    return csv_reader

def testKeys(m):
    try:
        print(m.api)
        print(m.net)
        print(m.org)
        getVlans(m)
    except: 
        return False
    return True

def getVlans(morg):
    api=morg.api
    net=morg.net
    org=morg.net
    api_client=morg.api_client

    if api == "" or net == "" or org == "":
        print("error(getVlans): API/NET/ORG is not populated")
        sys.exit()

    print("DONE")
    result = api_client.vlans.get_network_vlans(net)
    for r in result:
        vlanID = ""
        if 'id' in r:
            vlanID = r['id']
            morg.vlans.append(vlanID)
            if not vlanID in morg.target_interfaces:
                morg.target_interfaces[vlanID] = { 'ip':'', 'name':'', 'subnet':'' }
        if 'name' in r:
            morg.target_interfaces[vlanID]['name'] = r['name']
        if 'subnet' in r:
    #        print(r['subnet'])
            morg.target_interfaces[vlanID]['subnet'] = r['subnet']
            morg.subnets.append(r['subnet'])
        if 'applianceIp' in r:
            morg.target_interfaces[vlanID]['ip'] = r['applianceIp']
            morg.subnets.append(r['applianceIp'])

    #also add the statics it has just incase it's a 3rd party VPN or external route
    result2 = api_client.static_routes.get_network_static_routes(net)
    for r in result2:
        if 'subnet' in r:
            morg.subnets.append(r['subnet'])

    return result

#parses through lines and poplulates network_interfaces(Dict)
#used to identify "current" interfaces, to be used to swap for "new"
def find_interfaces(intName, lines,network_interfaces):
    for l in lines:
        cvl = intName.split('.')[1] #calculated VLAN from name
        if not cvl in network_interfaces:
            network_interfaces[cvl] = {'name':intName, 'vlan':'', 'ip':'', 'mask':''}
        if "vlan" in l.text:
            t_vlan = l.text.split()[1]
            if t_vlan.isdigit():
#                print("VLAN:"+ t_vlan)
                network_interfaces[cvl]['vlan'] = t_vlan
        if "ip address" in l.text:
            lt = l.text.split()
            if isIP(lt[2]) and isIP(lt[3]):
                network_interfaces[cvl]['ip'] = lt[2]
                network_interfaces[cvl]['mask'] = lt[3]
    return


#returns Boolean depending if the local subnet
def isLocal(morg, sub):
    if sub in morg.vlans: return True
    if sub in morg.iface: return True
    if sub in morg.subnets: return True
#    if '/' in sub:
#        print("this is where you'd make a static rule")

    return False

def isIP(temp):
    try:
        ip = ipaddress.ip_network(temp)
    except ValueError:
        return False
    return True

#takes input, IP address or Subnets, single or seperated by commas
#will replace all "old" addresses with newer ones discovered on the target network
def mapIP(morg,source):
    result=""
    old=source.split(",")
    for o in old:
#        print(o)
        if o in morg.mapping_table:
            #found a match, replace
            result += morg.mapping_table[o] + ","
            #print("REPLACED SOMETHING")
        else:
            #not found, put it back and move on
            result += o + ','
    
    return result[:-1]




def testFW(morg):
    api_client = morg.api_client
    net = morg.net
    org = morg.org
    
    collect = {}
    collect['network_id'] = net
    newFWrules = UpdateNetworkL3FirewallRulesModel()

    newFWrules.rules = []
    newFWrules.rules.append(RuleModel())
    newFWrules.rules[0].policy = "allow"
    newFWrules.rules[0].protocol = "Any"
    newFWrules.rules[0].src_cidr = "Any"
    newFWrules.rules[0].src_port = "Any"
    newFWrules.rules[0].dest_cidr = "Any"
    newFWrules.rules[0].dest_port = "Any"
    newFWrules.rules[0].comment = "TEST!"
    newFWrules.rules[0].syslog_enabled = False

    print(newFWrules.rules[0].syslog_enabled)

 
    try:
        collect['update_network_l3_firewall_rules'] = newFWrules 
        print(collect)
        result = api_client.mx_l3_firewall.update_network_l3_firewall_rules(collect)
        print(result)
        
    except APIException as e: 
        print(f'{e.response_code} error - {e.context.response.raw_body}?')

    return


def parseRules(morg):
    res = getVlans(morg)
    print("Target Network Interfaces:")
    for t in morg.target_interfaces:
        print(morg.target_interfaces[t])

    parse = CiscoConfParse('asa_to_mx_scrubbed.txt', syntax='asa')

    print("...parsing network interfaces...")
    int_objects = parse.find_objects(r'Port-channel1.')
    for element in int_objects:
        lines = element.children
        intName = element.text
        text = find_interfaces(intName, lines,morg.network_interfaces)

    print("Imported Config Network Interfaces:")
    for n in morg.network_interfaces:
        i=morg.network_interfaces[n]
        print("Vlan[" + i['vlan'] + "]  IP["+i['ip']+"] Mask["+i['mask']+"]")
    print()
    print()

    #now build the convertion table
    #dictionary, with "config-source" interface as index
    for n in morg.network_interfaces:
        old_ip = morg.network_interfaces[n]['ip']
        old_mask = morg.network_interfaces[n]['mask']
        if isIP(old_ip) and isIP(old_mask):
            temp_ip = ipaddress.ip_interface(old_ip+"/"+old_mask)
        else:
#            print("No original Subnet/Interface address to replace")
            continue
        old_subnet = str(temp_ip.network)
        c_vlan = int(morg.network_interfaces[n]['vlan'])
        if c_vlan in morg.target_interfaces:
            new_ip = morg.target_interfaces[c_vlan]['ip']
            new_subnet = morg.target_interfaces[c_vlan]['subnet']
        else:
#            print(str(morg.target_interfaces))
            print("warning(MAPPING): Missing interfaces on target system? VLAN["+str(c_vlan)+"] not seen")
           #exit()

#        print("VLAN["+str(c_vlan)+"] Old["+str(old_ip)+"] on ["+str(old_subnet)+"]")
#        print("VLAN["+str(c_vlan)+"] New["+str(new_ip)+"] on ["+str(new_subnet)+"]")
        morg.mapping_table[old_ip] = new_ip
        morg.mapping_table[old_subnet] = new_subnet

    print()
    print("**************  Mapping Table  ******************************")
    print(morg.mapping_table)
    print("*************************************************************")



def loadRules(morg,csv_reader):
    net = morg.net


    count = 0
    badlines = [] #
    collect = {}
    collect['network_id'] = net
    newFWrules = UpdateNetworkL3FirewallRulesModel()
    newFWrules.rules = []
    for c in csv_reader:
        if c[0] == 'policy': continue #header, move onto next item
    #    time.sleep(0.5)
        newFWrules.rules.append(RuleModel())
    #    for tc in range(len(c)):
    #        if len(c[tc]) == 0: c[tc] = 'Any'
    #        if len(c[tc]) <= 2: c[tc] = 'Any'
        count = len(newFWrules.rules)-1
        newFWrules.rules[count].policy = c[0]
        newFWrules.rules[count].protocol = c[1]
        if c[2] == 'Any' or c[2] == 'any' or isLocal(morg,mapIP(morg,c[2])):
            newFWrules.rules[count].src_cidr = mapIP(morg,c[2])
            newFWrules.rules[count].dest_cidr = mapIP(morg,c[4])
        elif len(c[2].split(',')) >= 1:
            addys = c[2].split(',')
    #        print("Length of SRC:"+str(len(addys)))
    #        print(addys)
            found = False
            filtered = ""
            for t in addys:
                if isLocal(morg, mapIP(morg,t)):
                    found = True
                    filtered += mapIP(morg,t) + ","
            if len(filtered) > 0:
                filtered = filtered[:-1] #pull off the last ,

            if not found:
                newFWrules.rules[count].src_cidr = "Any"
                newFWrules.rules[count].dest_cidr = mapIP(morg,c[4])

            else:
                newFWrules.rules[count].src_cidr = filtered
    #            newFWrules.rules[count].src_cidr = mapIP(c[2])
                newFWrules.rules[count].dest_cidr = mapIP(morg,c[4])



                
        else:
            print("error(CSVparser): unknown")
    #        print(c[2])
            exit()
        
        newFWrules.rules[count].src_port = c[3]
        newFWrules.rules[count].dest_cidr = mapIP(morg,c[4])
        newFWrules.rules[count].dest_port = c[5]
        newFWrules.rules[count].comment = c[6]
        newFWrules.rules[count].syslog_enabled = False
        
        destCIDR = newFWrules.rules[count].dest_cidr
        if not isIP(destCIDR) and not ',' in destCIDR and not "Any" and not "any" :
     #      print(newFWrules.rules[count].dest_cidr)
            sys.exit("ERROR")

        #do some logic processing
        prot = newFWrules.rules[count].protocol.lower()
        src  = newFWrules.rules[count].src_cidr.lower()
        dst  = newFWrules.rules[count].dest_cidr.lower()
        srcp = newFWrules.rules[count].src_port.lower()
        dstp = newFWrules.rules[count].dest_port.lower()
        pol  = newFWrules.rules[count].policy.lower()
        if src == "any" and dst == "any" and srcp == "any" and dstp == "any" and pol == "allow":
            foobar = newFWrules.rules.pop(count)
            print("warning- popped any/any/any/any rule! discarding") 
            #do nothing here, rule won't be saved which is desired behavior
            
        
        #use case where there are ports assigned, but Protocl is TCPUDP or Any
        #this adds a second rule for TCP and UDP
        elif prot == "any":
            if not srcp == "any" or not dstp == "any":
                newFWrules.rules[count].protocol = "tcp"
                newFWrules.rules.append(RuleModel())
                newFWrules.rules[count+1].policy = newFWrules.rules[count].policy
                newFWrules.rules[count+1].protocol = "udp"
                newFWrules.rules[count+1].src_cidr = src
                newFWrules.rules[count+1].src_port = srcp
                newFWrules.rules[count+1].dest_cidr = dst
                newFWrules.rules[count+1].dest_port = dstp
                newFWrules.rules[count+1].comment = newFWrules.rules[count].comment
                newFWrules.rules[count+1].syslog_enabled = newFWrules.rules[count].syslog_enabled
#                print("MADE A NEW RULE!")

        #print(newFWrules.rules[count].src_port)
    
    collect['update_network_l3_firewall_rules'] = newFWrules
    return collect


def importRules(morg,collect):
    api_client = morg.api_client
    try:
    #    print(collect)
    #    nfr = 209
    #    print("Rule["+str(nfr)+"] DestCIDR["+newFWrules.rules[nfr].dest_cidr+"]")
    #    exit()
        result = api_client.mx_l3_firewall.update_network_l3_firewall_rules(collect)
    #    print(result)
    except APIException as e: 
        print()
        print(f'{e.response_code} error - {e.context.response.raw_body}?')

def clearRules(morg):
    testFW(morg)
    return

def generateRules(config_file):
    asa_to_mx.asa_to_mx(config_file)
    return

def printhelp():
    #prints help text

    print('This is a script to manage firewall rules. Import legacy ASA configs into target MX network')
    print('')
    print('To run the script, enter:')
    print('python3 mx_import.py -k <key> -o <org> -n <networkID> -c command <ASA CONFIG FILE>')
    print("[commands] = write, test, clear")

def main(argv):
    #python mxfirewallcontrol -k <key> -o <org> -n <networkID> -c <command> <ASA Config>

    morg = Meraki_org()
    
    #set default values for command line arguments
    arg_apikey  =   ''
    arg_org     =   ''
    arg_network =   ''
    commands =      ['write', 'test', 'clear']
    arg_command =   'test' #default test
    arg_file =      '' 
    
    #get command line arguments
    try:
        opts, args = getopt.getopt(argv, 'k:o:n:c:')
    except getopt.GetoptError:
        printhelp()
        sys.exit(2)

    for opt, arg in opts:
        if   opt == '-h':
            printhelp()
            sys.exit()
        elif opt == '-k':
            arg_apikey  = arg
            if not len(arg_apikey) == 40:
                print("error(ARGV): API Key incorrect length")
                sys.exit()

        elif opt == '-o':
            arg_org     = arg
            if not len(arg_org) > 5:
                print("error(ARGV): Org ID incorrect length")
                sys.exit()

        elif opt == '-n':
            arg_network = arg
            if not len(arg_network) == 20:
                print("error(ARGV): Network ID incorrect length")
                sys.exit()
        elif opt == '-c':
            arg_command   = arg
            print(arg)
            if not arg_command in commands:
                print("error(ARGV): invalid command")
                sys.exit()

    if len(argv) <= 1:
        printhelp()
        print()
        print()
        sys.exit(2)

    arg_file = argv[len(argv)-1]

    if not os.path.exists(arg_file):
        print("error(ARGV): Config file/filename is invalid")
        print(argv)
        print(opts)
        sys.exit()

    print("Loading config file ["+ argv[len(argv)-1] +"]")

   #check if all parameters are required parameters have been given
    if arg_apikey == '' or arg_org == '' or arg_network == '':
        printhelp()
   #     clearRules()
        sys.exit(2)
    

    morg.set(arg_apikey, arg_org, arg_network)
    api_client = morg.api_client
    API_WORKS = False
    try:
        res = api_client.organizations.get_organizations()
        API_WORKS = True
        print("(API) Connected! Settings Valid")
    except:
        print("error(API): API key is invalid")
        print()
        sys.exit()


    generateRules(arg_file)
    print("Done Generating rules.....")

    parseRules(morg)
    print("Done Parsing rules.....")

    rule_file = "mx_l3fw_rules_"+arg_file+".csv"
    if not os.path.exists(rule_file):
        print("error(MAIN): Can't load/find processed rule file")
        print("RULE FILE [" + rule_file + "]")
        sys.exit()

    csv_reader = loadInputFile(rule_file)
    print("Loaded sanitized rules")

    newFW_collect = loadRules(morg,csv_reader)
    print("Done Loading rules.....")

    if arg_command == "write":
        importRules(morg,newFW_collect)
        print("Done Importing rules....")
    elif arg_command == "test":
        print("Test complete, looks good so far")
    elif arg_command == "clear":
        testFW(morg)
        print("CLEARED!")

    print()
    print("SCRIPT COMPLETE!")
    return

if __name__ == '__main__':
    main(sys.argv[1:])

