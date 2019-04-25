# -*- coding: utf-8 -*-
###
# (C) Copyright (2012-2019) Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# Author : Vikram Fernandes
###

from pprint import pprint

# from config_loader import try_load_from_file
from hpOneView.exceptions import HPOneViewException
from hpOneView.oneview_client import OneViewClient

import argparse
import getpass
import socket
import os


##################################################################
# Function to build arguments
#
##################################################################
def buildArguments():

    ap = None
    ap = argparse.ArgumentParser(
        description='This script updates existing server profiles with a new server profile template ')
    ap.add_argument("-pt", "--print-templates", action='store_true',
                    dest="print_templates", help="Print configured Server profile templates ")
    ap.add_argument("-pp", "--print-profiles", action='store_true', dest="print_profiles",
                    help="Print configured profiles and associated templates ")        
    ap.add_argument("-f", "--file",   dest="file",  help="File containing list of Server Profile names")
    ap.add_argument("-t", "--template",   dest="sp_template", help="Template name")
    ap.add_argument("-a", "--appliance",   dest="appliance", help="Appliance IP", required=True)

    return ap

##################################################################
# Function to retrieve user details
#
##################################################################
def get_para(msg):
    """
    Read a parameter
    :param msg: Message to be displayed
    :return:
    """
    val = None
    is_valid = 0
    while not is_valid:
        val = str(input(msg).lstrip())
        if len(val) > 0:
            is_valid = 1
        else:
            is_valid = 0
    return val

##################################################################
# Function to validate appliance
#
##################################################################
def validate_appliance(ip_in):
    """
     Validate IPv4 address
    :param ip: IPv4 Address
    :return: IP Address    
    """
    try:  
        ip_out = socket.gethostbyname(ip_in) 
        socket.inet_aton(ip_out)
        #print ("appliance ip {}".format(ip_out))
        #print ("appliance {} reachable".format(ip))
        return 1
    except socket.error:
        # not legal
        print ("ERROR: Appliance {} NOT reachable".format(ip))
        return 0

##################################################################
# Function to retrieve user credentials and build dict
#
##################################################################
def requestCredentials(appliance):
    UserName = get_para("Username: ")
    password = getpass.getpass()
    config = {
        "ip": appliance,
        "credentials": {
            "userName": UserName,
            "password": password,
        },
        "api_version": 800
    }

    return config

##################################################################
# Function to switch template in profiles
#
##################################################################
def switch_template_in_profiles(oneview_client, template_in, file_in):

    template = oneview_client.server_profile_templates.get_by_name(template_in)
    print(template['name'], template['uri'])

    #print("\nGet list of all server profiles")
    #all_profiles = oneview_client.server_profiles.get_all()
    #for profile in all_profiles:
    #    print('  %s' % profile['name'])

    with open(file_in, "r") as list:
            for line in list:
                    line = line[:-1]
                    try:
                            print()
                            print("Profile to update : {}".format(line))
                            profile = oneview_client.server_profiles.get_by_name(
                                line)
                            profile_to_update = profile.copy()
                            print("Before complete for Profile {} ,     template URI {}".format(profile_to_update['name'],
                                                                                                profile_to_update[
                                                                                                    'serverProfileTemplateUri']))
                            profile_to_update["serverProfileTemplateUri"] = (
                                template["uri"])
                            profile_updated = oneview_client.server_profiles.update(resource=profile_to_update,
                                                                                    id_or_uri=profile_to_update["uri"])
                            print("Update complete for Profile {} , New template URI {}".format(profile_updated['name'],
                                                                                                profile_updated['serverProfileTemplateUri']))
                            print()
                    except HPOneViewException as e:
                            print("Profile error")
                            print(e.msg)

##################################################################
# Function to print configured templates
#
##################################################################
def print_templates(oneview_client):
    #print("\nList of all server profile templates")
    sp_templates = oneview_client.server_profile_templates.get_all()
    print("\n")
    print ('   Server Profile Templates')
    print ('   ========================')
    for sp_template in sp_templates:
        print('   {:50}'.format(sp_template['name']))

##################################################################
# Function to print configured profiles with templates
#
##################################################################
def print_profiles(oneview_client):
    print("\n")
    print("   {:50}\t{}".format("Server Profiles", "Server Profile Templates"))
    print("   {:50}\t{}".format("===============", "========================"))
    profiles = oneview_client.server_profiles.get_all()
    for profile in profiles:
        sp_template = oneview_client.server_profile_templates.get(profile['serverProfileTemplateUri'])
        #print(profile['serverProfileTemplateUri'])
        #print(sp_template)        
        print('   {:50}\t{}'.format(profile['name'],sp_template['name']))

##################################################################
# Function to validate if template exists
#
##################################################################
def validate_template(oneview_client, template_in):
    template = oneview_client.server_profile_templates.get_by_name(template_in)
    #print(template)
    if template is None:
        print ("\nTemplate : {} - not found".format(template_in))
        return 0
    else:
        return 1

##################################################################
# Function to validate if file exists
#
##################################################################
def validate_file(file_in):
    # Check in current directory 
    if os.path.isfile(file_in):
        full_path = os.path.abspath(file_in)
        #print ("file path {} ".format(full_path))
        return 1
    else:
        print ("ERROR: File {} NOT available".format(file_in))
        return 0
    

##################################################################
# Main module
#
##################################################################
def main():

    # Review arguments
    args = buildArguments().parse_args()
    fileCheck = False
    templateCheck = False

    if args.appliance:
        if  not validate_appliance(args.appliance):
            exit(1)
    
    if args.file:
        if not validate_file(args.file):
            exit(1)  
        else:
            fileCheck = True      

    # connect to OneView    
    config_out = requestCredentials(args.appliance)
    #print (config_out)
    oneview_client = OneViewClient(config_out)
    print ("\nLogin to OneView successful")

    if args.print_templates:
        print_templates(oneview_client)

    if args.print_profiles:
        print_profiles(oneview_client)

    if args.sp_template:
        if validate_template(oneview_client, args.sp_template):
            print ("\nTemplate : {} - is valid".format(args.sp_template))
            templateCheck = True
            
    if templateCheck and fileCheck:
        switch_template_in_profiles(oneview_client, args.template, args.file)
    else:
        print ("\nFile or Template not validated")
    
    exit(0)


##################################################################
# Start module
#
##################################################################
if __name__ == "__main__":
	import sys
	sys.exit(main())
