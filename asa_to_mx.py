#!/usr/bin/python3

READ_ME = '''
=== PREREQUISITES ===
Install both requests & ciscoconfparse modules:
pip[3] install --upgrade requests
pip[3] install --upgrade ciscoconfparse

Include both files port_mappings.csv (Cisco IOS port names to numbers), and also
acl_list.txt (containing names of extended ACLs to parse) in the same folder.

=== DESCRIPTION ===
Extracts ASA extended ACL configuration to CSV ready for MX import.

'''

import csv
from datetime import datetime
import getopt
import ipaddress
import logging
import sys
import re
from ciscoconfparse import CiscoConfParse

SYSLOG_ENABLED = False

# Added fluff text in ASA v7 config that causes errors
more_line_text = '''<--- More --->
              
'''

# Prints READ_ME help message for user to read
def print_help():
    lines = READ_ME.split('\n')
    for line in lines:
        print('# {0}'.format(line))

logger = logging.getLogger(__name__)

def configure_logging():
    logging.basicConfig(
        filename='{}_log_{:%Y%m%d_%H%M%S}.txt'.format(sys.argv[0].split('.')[0], datetime.now()),
        level=logging.DEBUG,
        format='%(asctime)s: %(levelname)7s: [%(name)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def isIP(temp):
    try:
#        ip = ipaddress.ip_address(temp)
        ip = ipaddress.ip_network(temp)
    except ValueError:
        return False
    return True

#takes two IP addresses and returns string containing all IPs in that range
# 192.168.100.1/32, 192.168.100.2/32, etc
def enum_IP(ip1, ip2):
    output = ''
#    print("IP1["+ip1+"]")
#    print("IP2["+ip2+"]")
    start_ip = ipaddress.IPv4Address(ip1)
    end_ip = ipaddress.IPv4Address(ip2)
    for ip_int in range(int(start_ip), int(end_ip)+1):
#        print(ipaddress.IPv4Address(ip_int))
        output += str(ipaddress.IPv4Address(ip_int)) + "/32,"
    return output[:-1]

#clever feature to return netmask bit-count
def nm_bits(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

# Function to convert ASA's "object-group network" blocks
def asa_to_mx_l3(network_object_lines, network_mappings):
    output = ''
    print("mx_l3")  
    for line in network_object_lines:
        # Convert to list of elements, separated by whitespace
        commands = line.text.split()
        
        # First element should be "network-object", exit if not
        if commands[0] == 'network-object':
            commands.remove('network-object')
        elif commands[0] == 'group-object':
            commands.remove('group-object')
            print("Group-object: " + commands[0])
            temp_net = network_mappings[commands[0]]
#            print("TEMP_NET: "+ str(temp_net))
#            commands = temp_net.split(',')
            output += network_mappings[commands[0]]+","
            print("OUTPUT:" + output)
            continue
            #return output
            #for t in commands:
            #    output += t + ','
            
           #return output[:-1]
        elif commands[0] == "host": #solves single host network object
            if isIP(commands[1]): return commands[1]+"/32"
            else:
                print("BOOOOOO")
                exit()
        elif commands[0] == "range": #solves the IP-range network object
            if isIP(commands[1]) and isIP(commands[2]):
                print("BOTH ARE VALID!!!")
                ipRange=enum_IP(commands[1],commands[2])
                print(str(ipRange))
                return ipRange
        elif commands[0] == "subnet": #solves the subnet range network object
            if isIP(commands[1]) and isIP(commands[2]):
                print("VALID SUBNET IPS")
                bits = nm_bits(commands[2])
                ip = ipaddress.ip_interface('{0}/{1}'.format(commands[1], bits))
                output += ip.with_prefixlen
                print(output)
                return output

        else: #something new and unknown
            print("NOT an network-object or group")
            print("COMMANDS: "+ str(commands))
            print(line.text)
            sys.exit(line.text)


        if len(commands) == 1:#if there's one element, it'll be a group object
            if '/' in commands[0] and not commands[0] in output: #if CIDR format, "10.0.0.0/8"
                t_ip = commands[0].split('/')
                ip = ipaddress.ip_interface('{0}/{1}'.format(t_ip[0], t_ip[1]))
                output += ip.with_prefixlen
                print("OUTPUT:" + ip)

            print("ONE COMMAND"+ str(commands))  #<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<START HERE

            if commands[0] in network_mappings:
                print("Yes in mappings")
                print(network_mappings[commands[0]])
                output += network_mappings[commands[0]] 
                continue
                #this is an array, not sure how that'll work
            else:
                if isIP(commands[0]):
                    print("YES IT IS")
        #            output += commands[0] + ','
                else:
                    print("BIG NOPE")
                    print(str(commands))
                    print(isIP(commands[0]))
                    sys.exit(line.text)
 #       elif len(commands) != 2:# Should have two remaining elements
 #           if isIP(commands[0]):
 #               for i in commands:
 #                   if isIP(i): output += i + ','
 #           continue
 
#            print("Not enough params")
#            print("err(COMMANDS): " + str(commands))
#            print("Length:"+str(len(commands)))
#            return output
#            sys.exit(line.text)#


        # Parse and concatenate to output
        if commands[0] == 'host':
            ip = commands[1]
            # Host or /32
            if ip in network_mappings:
                output += network_mappings[ip]
            else:
                output += '{0}/32'.format(ip)
        elif commands[0] == 'object':
            print("Object: " + str(commands))
            if commands[1] in network_mappings: 
                print("ITS HERE!")
                print(network_mappings[commands[1]])
                ip = network_mappings[commands[1]]
                output += ip

            else:
                print("NOT FOUND"+ str(commands[1]))
                try:
                    ip = ipaddress.ip_address(commands[1])
                    print('%s is a correct IP%s address.' % (ip,ip.version))
                    output += '{0}/32'.format(ip)
                except ValueError:
                    print("error(parse): not object or IP!!!")
                    print("address/netmask is invalid: %s" %  str(commands[1]))
                    print(network_mappings)
                    sys.exit(line.text)
                
        else:
            # IP subnet
            #print(commands[0])
            if len(commands) > 1 and len(commands) <= 2: 
                print(str(commands))
                if commands[0].find('/') == -1:
                    ip = ipaddress.ip_interface('{0}/{1}'.format(commands[0], commands[1]))
                    if isIP(ip): output += ip.with_prefixlen
            else:
                print("Just one item")
                print("err(single item): catchall")
                print("COMMANDS:" + str(commands))
                print("OUTPUT:" + output)
                #sys.exit(line.text)

        # Add commas in between
        output += ','

    # Remove final unneeded comma
    return output[:-1]

# Helper function to enumerate all ports, whether separated by commas or defined by ranges
def enumerate_ports(s):
    result =  sum(((list(range(*[int(j) + k for k,j in enumerate(i.split('-'))]))
        if '-' in i else [int(i)]) for i in s.split(',')), [])

    # Remove brackets and whitespaces from string representation, and return result
    result = str(result)
    result = result.strip('[')
    result = result.rstrip(']')
    result = result.replace(' ', '')
    return result

# Function to convert ASA's "object-group service" blocks
def asa_to_mx_l4(service_object_lines, port_mappings):
    output = ''
    for line in service_object_lines:
        # Convert to list of elements, separated by whitespace
        commands = line.text.split()
    
        # First element should be "port-object", exit if not
        if commands[0] == 'port-object':
            commands.remove('port-object')
        elif commands[0] == 'description':
            return ""
        elif commands[0] == 'group-object':
            commands.remove('group-object')
        elif commands[0] == 'service-object':
            commands.remove('service-object')

        else:
            print("Error ASA_TO_MX_L4")
            sys.exit(line.text)

        if commands[0] == 'icmp':
            continue
        # Should have either two (eq) or three (range) remaining elements
        if len(commands) == 2 and commands[0] == 'eq':
            port = commands[1]
            if port.isdigit():
                output += port
            else:
                output += port_mappings[port]
        elif len(commands) == 3 and commands[0] == 'range':
            output += '{0}-{1}'.format(commands[1], commands[2])
        elif len(commands) == 1:
            #port = commands[0]
            print("Single Port usecase")
            output += port_mappings[commands[0]]
        elif len(commands) >=3 and commands[2] == 'eq': #nico added, service-object usecase
            port = commands[3]
            if port.isdigit():
                output += port
            else:
                output += port_mappings[port]
            #output += commands[3]
            #print("Service object usecase " + str(output) + " RAW[" + str(commands) + "]")
            #print(port_mappings['www'])
        elif len(commands) >=3 and commands[2] == 'range':
            output += '{0}-{1}'.format(commands[3], commands[4])
            print("Service object Range usecase " + str(output) + " RAW[" + str(commands) + "]")
        else:
            print("Error ASA_TO_MX_L4 port parsing")
            sys.exit(line.text)

        # Add commas in between
        output += ','

    # Remove final unneeded comma, and enumerate all ports including ranges
    return enumerate_ports(output[:-1])


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
#                t_ip = lt[2] + "/" + lt[3]
#                print(lt)
                network_interfaces[cvl]['ip'] = lt[2]
                network_interfaces[cvl]['mask'] = lt[3]
    return


def asa_to_mx(arg_file):
    # Read port_mappings.csv file for name/number pairs, such as (www, 80)
    # https://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/ref_ports.html#wp1007738
    port_mappings = dict()
    csv_file = open('port_mappings.csv')
    reader = csv.reader(csv_file, delimiter=',', quotechar='"')
    next(reader, None)
    for row in reader:
        [name, tcpudp, number, description] = row
        port_mappings[name] = number

    # Set the CSV output file and write the header row
    #timenow = '{:%Y%m%d_%H%M%S}'.format(datetime.now())
    #filename = 'mx_l3fw_rules_{0}.csv'.format(timenow)
    filename = 'mx_l3fw_rules_{0}.csv'.format(arg_file)
    output_file = open(filename, mode='w', newline='\n')
    field_names = ['policy','protocol','srcCidr','srcPort','destCidr','destPort','comment','logging']
    csv_writer = csv.DictWriter(output_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL, fieldnames=field_names)
    csv_writer.writeheader()

    # Open "sh run" output file and parse
    with open(arg_file, 'U') as f:
        newText=f.read()
        while more_line_text in newText:
            newText=newText.replace(more_line_text, '')
    with open('asa_to_mx_scrubbed.txt', 'w') as f:
        f.write(newText)
    
    parse = CiscoConfParse('asa_to_mx_scrubbed.txt', syntax='asa')
   
    print("...scrubbed config")
    # Parse out name objects for ASA v 7
    network_mappings = {}
    name_objects = parse.find_objects(r'name ')
    for element in name_objects:
        name = element.text
        if name[:5] != 'name ':
            continue
        name = name.replace('name ', '').split()
        network_mappings[name[1]] = name[0] +'/32'
    print("...looked up names for asa V7")

    print("...parsing network interfaces...")
    network_interfaces = {}
    int_objects = parse.find_objects(r'Port-channel1.')
    for element in int_objects:
        lines = element.children
        intName = element.text
        text = find_interfaces(intName, lines,network_interfaces)
        
    print(network_interfaces)
    #exit()

    #parse "object network" 
    solo_objects = parse.find_objects(r'object network')
    for element in solo_objects:
        name = element.text.replace('object network ', '')
        lines = element.children
        text = asa_to_mx_l3(lines, solo_objects)
        network_mappings[name] = text

    print(".. Solo objects parsed")

# Parse "object-group network" blocks in lines 143-441
    network_objects = parse.find_objects(r'object-group network')
    for element in network_objects:
        name = element.text.replace('object-group network ', '')
        lines = element.children
        print(lines)
        text = asa_to_mx_l3(lines, network_mappings)
        network_mappings[name] = text

    print("parsed object-groups network")
    # Parse "object-group service" blocks, in lines 442-571
    # Add to loaded port_mappings from file
    service_objects = parse.find_objects(r'object-group service')
    for element in service_objects:
        name = element.text.replace('object-group service ', '')
        name = name.split()[0]
        lines = element.children
        text = asa_to_mx_l4(lines, port_mappings)
        port_mappings[name] = text
    print("parsed object-group service")
    
    # Default deny rule, to be added at very end
    network_mappings['any'] = 'Any'
    default_deny = False
 
    f = open("networkmappings_raw.txt","w+")
    f.write(str(network_mappings))
    f.close()
    p = open("portmappings_raw.txt","w+")
    p.write(str(port_mappings))
    p.close()


    print("Checking ACL lists to parse...")
    # Open acl_list.txt, which determines which extended ACLs to parse
    acl_list = open('acl_list.txt')
    for acl_line in acl_list:
        acl_name = acl_line.strip()
        acl_block = parse.find_blocks(r'access-list {0}'.format(acl_name))
        for command in acl_block:
            rule = {}
            line = command.strip()
            #line = line.split('extended ')[1]
            line = line.replace('extended', '')
            line = line.split(acl_name)[1]
            # finished edits
            command = line
            fields = line.split()
            # Remove irrelevant terms
            fields = [x for x in fields if x not in ('eq', 'object-group', 'echo-reply', 'unreachable', 'time-exceeded', 'object')]
            policy = fields.pop(0)
            if policy == 'permit':
                rule['policy'] = 'allow'
            elif policy == 'deny':
                rule['policy'] = 'deny'
            elif policy == 'remark':
                #print("Remark found and ignored")
                continue
            else:
                print("error(ACL): allow/deny")
                print(fields)
                sys.exit(command)

            protocol = fields.pop(0)
            if protocol == 'ip':
                rule['protocol'] = 'any'
            elif protocol == 'TCPUDP':
                rule['protocol'] = 'any'
            elif protocol == 'icmp':
                rule['protocol'] = 'icmp'
            elif protocol == 'udp':
                rule['protocol'] = 'udp'
            elif protocol == 'tcp':
                rule['protocol'] = 'tcp'
            else:
                print("error(ACL): protocol expected ["+protocol+"]")
                print(str(fields))
                if protocol in port_mappings:
                    print("YUP its a PORT range")
                    print(port_mappings[protocol])
                    #rule['protocol'] = 'any'
                    rule['destPort'] =  port_mappings[protocol]
                    print(str(rule))
                    #exit()
                else:
                    print("Unknown protocol")
                    exit()
                #fields.insert(0,protocol)


            srcCidr = fields.pop(0)
            if srcCidr == "any4": srcCidr = "any"
             
            if srcCidr in network_mappings: 
                rule['srcCidr'] = network_mappings[srcCidr]
            elif isIP(srcCidr) and isIP(fields[0]):
              #  print("ADDY:" + srcCidr +"/"+ fields[0])
                ip = ipaddress.ip_interface('{0}/{1}'.format(srcCidr, nm_bits(fields[0])))
                newSrc = ip.with_prefixlen
                if isIP(newSrc):
                    next_field = fields.pop(0) #burn one off, for netmask
#                    next_field = fields.pop(0) #burn one off, for netmask

                    rule['srcCidr'] = newSrc
                else:
                    print("Horrific srcDest="+ newDest)
                    print("Command:" + command)
                    print("error(NextField)342:" + next_field)
                    print(str(fields))
                    print(str(rule))
                    exit()
            elif srcCidr == "host" and isIP(fields[0]):
                rule['srcCidr'] = fields[0]+"/32"
                next_field = fields.pop(0)
#                next_field = fields.pop(0)
#                print(rule['srcCidr'])
#                print(next_field)
#                sys.exit(command)
            



            next_field = fields.pop(0)

          #  rule['srcPort'] = 'any' #cheater line
            if next_field in port_mappings:
                if next_field == 'any':
                    rule['srcPort'] = 'Any'
                else:
                    rule['srcPort'] = port_mappings[next_field]
                next_field = fields.pop(0)
            elif next_field in network_mappings:
                rule['srcPort'] = 'Any'  #HERE
                rule['destCidr'] = network_mappings[next_field]
                if len(fields) > 0: next_field = fields.pop(0)
            elif next_field == 'host':
                rule['srcPort'] = 'Any'
                next_field = fields.pop(0)
                if isIP(next_field):
                    rule['destCidr'] = next_field + "/32"
                    if len(fields) > 0: next_field = fields.pop(0)
                else:
                    print("error(ACL): insane error")
                    exit()
            elif next_field.isdigit():
                if int(next_field) < 65535 and int(next_field) > 0:
                    rule['srcPort'] = next_field
                    next_field = fields.pop(0)
             
           ### this should be destination

            if len(fields) > 1 and isIP(next_field) and isIP(fields[0]):

                ip = ipaddress.ip_interface('{0}/{1}'.format(next_field, nm_bits(fields[0])))
                newDest = ip.with_prefixlen
                if isIP(newDest): 
                    rule['destCidr'] = newDest
                    next_field = fields.pop(0) #pull off the mask
                    next_field = fields.pop(0) #pull off the mask

#                    if len(fields) > 0: next_field = fields.pop(0) #queue the next one
                   # else:
                    #    sys.exit("UNKNOWN")

                else:
                    print("Horrific newDest="+ newDest)
                    print("Command:" + command)
                    print("error(NextField)DST:" + next_field)
                    print(str(fields))
                    print(str(rule))
                    sys.exit(command)

            else:
                if 0 == 1:
                    #am i dropping anything here?
                    print("Command:" + command)
                    print("warning(NextField)?!?:" + next_field)
                    print(str(fields))
                    print(str(rule))
                    #sys.exit(command)
            

            #next_field = fields.pop(0)

            rule['destPort'] = ''
            if len(fields) == 0:
                if not 'destCidr' in rule: rule['destCidr'] = 'Any'
                rule['destPort'] = 'Any'
            elif next_field == 'any' or next_field == 'any4':
                if not 'destCidr' in rule: rule['destCidr'] = 'Any'
                next_field = fields.pop(0)
            elif next_field in port_mappings: 
                rule['destPort'] = port_mappings[next_field]
            elif len(fields) == 1:
                
                if next_field.isnumeric():
                    rule['destPort'] = next_field
                elif next_field == "log":
                    if rule['destPort'] == '': rule['destPort'] = 'Any'
                elif not isIP(next_field) and next_field in port_mappings:
                    rule['destPort'] = port_mappings[next_field]
                else:
                    print("Command:" + command)
                    print("error(NextField):" + next_field)
                    print(str(fields))
                    print(str(rule))
     
#                    sys.exit("ERROR!!@#!@$@!$")
                

            if next_field == "any4" or next_field == "any":
                rule['destCidr'] = 'Any'
                if len(fields) > 0: next_field = fields.pop(0)
                
            elif next_field in network_mappings:
                #could be a group of device IPs
                print("status(ACL): Network Object detected ["+str(next_field)+"]")
                rule['srcPort'] = 'Any'
                rule['destCidr'] = network_mappings[next_field]
                rule['destPort'] = 'Any'
            elif len(fields) > 0 and isIP(next_field) and isIP(fields[0]) and nm_bits(fields[0]) >= 8:
                #so basically use case of a "10.0.0.0 255.0.0.0 " host
                #print("warning(ACL): seperate source & mask "+str(next_field)+"/"+str(fields[0]))
                rule['srcPort'] = 'Any'
                rule['destCidr'] = next_field + "/" + str(nm_bits(fields[0]))
                rule['destPort'] = 'Any'
#                print(rule['destCidr'])
            elif next_field.isdigit():
                print("NextField: "+ str(next_field))
                if int(next_field) < 65535 and int(next_field) > 0:
                    rule['destPort'] = next_field
                else:
                    print("err(ACL): is digit, not in range")
                    print("fields: "+str(fields))
                    sys.exit(command)
            elif next_field in port_mappings:
                rule['destPort'] = port_mappings[next_field]
        
            else:
                #ANYTHING landing here should be fixed

                print("warning(ACL): keyword["+next_field+"]")
                print("fields: "+str(fields))
                print(next_field)
                print(rule)
#                sys.exit(command)

            if next_field == "range":
                rule['destPort'] = enumerate_ports(fields[0] + "-" + fields[1])
                next_field = fields.pop(0)
                next_field = fields.pop(0)
                if len(fields) > 0: next_field = fields.pop(0)

            #cheater function (looks for empty fields and sets to any)
            if len(fields) > 0 and rule['destPort'] == "":
                next_field = fields.pop(0)
                print('')
                if next_field == "log":
                    if rule['destPort'] == "": rule['destPort'] = 'Any'
                elif next_field.isdigit():
                    rule['destPort'] = next_field
                elif next_field == "range":
                    port_range = (fields[0] +"-"+fields[1])
                    rule['destPort'] = enumerate_ports(port_range)
                elif next_field in port_mappings:
                    rule['destPort'] = port_mappings[next_field]
                else:
                    print("error(emptyField): No DestPort")
                    print("Current Command: "+ next_field)
                    print("Fields:" + str(fields))
                    print("RULES:" + str(rule))
                    print("Commands:" + str(command))
                    sys.exit(command)
            elif rule['destPort'] == "":
                rule['destPort'] = "Any"

            
            for r in rule:
                if len(rule[r]) < 2:
                    print("error(Fields): Empty field")
                    print("RULES:" + str(rule))
                    print("Commands:" + str(command))
                    sys.exit(command)
            if not 'destCidr' in rule:
                print(rule)
                print("error(end): No destCIDR, something went terribly wrong")
                sys.exit(command)
            if not 'protocol' in rule:
                rule['protocol'] = 'Any'
            if not 'srcPort' in rule:
                print(rule)
                print("error(end): No sourcePort ")
                rule['srcPort'] = 'Any'

            print("******")
            print("Command:" + command)
            print(str(fields))
            print("FinalRule: " + str(rule))
            print("******")


            if rule == {'policy': 'deny', 'protocol': 'any', 'srcCidr': 'Any', 'srcPort': 'Any', 'destCidr': 'Any', 'destPort': 'Any'}:
                default_deny = True
                continue

            rule['comment'] = command
            rule['logging'] = SYSLOG_ENABLED
            csv_writer.writerow(rule)

    if default_deny:
        csv_writer.writerow({'policy': 'deny', 'protocol': 'any', 'srcCidr': 'Any', 'srcPort': 'Any', 'destCidr': 'Any', 'destPort': 'Any', 'comment': 'Default deny ip any any', 'logging': SYSLOG_ENABLED})

    output_file.close()
    print('Output CSV written to file {0}'.format(filename))

