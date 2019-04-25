# -*- coding: utf-8 -*-
###
# (C) Copyright (2012-2017) Hewlett Packard Enterprise Development LP
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
###

from pprint import pprint

# from config_loader import try_load_from_file
from hpOneView.exceptions import HPOneViewException
from hpOneView.oneview_client import OneViewClient

config = {
    "ip": "",
    "credentials": {
        "userName": "Administrator",
        "password": "",
    },
    "api_version": 600
}

# Try load config from a file (if there is a config file)
# config = try_load_from_file(config)

oneview_client = OneViewClient(config)

# Get all Profile Templates	
print("\nGet list of all server profile templates")
template = oneview_client.server_profile_templates.get_by_name("NewTemplate")

print(template['name'],template['uri'])

print("\nGet list of all server profiles")
all_profiles = oneview_client.server_profiles.get_all()
for profile in all_profiles:
    print('  %s' % profile['name'])

with open("Profiles.list", "r") as list:
        for line in list:
                line = line[:-1]
                try:
                        print()
                        print ("Profile to update : {}".format(line))
                        profile = oneview_client.server_profiles.get_by_name(line)
                        profile_to_update = profile.copy()
                        print("Before complete for Profile {} ,     template URI {}".format(profile_to_update['name'],
                                                                                            profile_to_update[
                                                                                                'serverProfileTemplateUri']))
                        profile_to_update["serverProfileTemplateUri"] = (template["uri"])
                        profile_updated = oneview_client.server_profiles.update(resource=profile_to_update,
                                                                                id_or_uri=profile_to_update["uri"])
                        print ("Update complete for Profile {} , New template URI {}".format(profile_updated['name'],
                                                                                             profile_updated['serverProfileTemplateUri']))
                        print()
                except HPOneViewException as e:
                        print("Profile error")
                        print(e.msg)


