#!/usr/bin/env python2.7
##
# Copyright 2015 Telefónica Investigación y Desarrollo, S.A.U.
# This file is part of reencryption PSA
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# For those usages not covered by the Apache License, Version 2.0 please
# contact with: secured@tid.es

# Class FindRules Copyleft 2013 Osama Khalid.
##

import re
import xml.etree.ElementTree as ET


def request(context,flow):
	replacer = FindRules('default.rulesets')
	if flow.request.scheme=='http':
		url=replacer.find('http://'+flow.request.pretty_host(hostheader=True)+flow.request.path)
		if url:
			flow.request.url=url
class FindRules:
    def __init__(self, filename):
        self.extract_rulesets(filename)

    def verify_target(self, target, host):
        matching_target = target.strip("*.")
        matching_target = matching_target.strip(".*")
        if target.startswith("*."):
            if host.endswith(matching_target):
                #print target, "matches", host
                return True
        elif target.endswith(".*"):
            if host.startswith(matching_target):
                #print target, "matches", host
                return True
        else:
            if host == matching_target:
                #print target, "matches", host
                return True

    def convert_to_python(self, matching, replacement):
        """Instead of $1 that is used by Javascript,
        Python uses \1."""
        new_matching = matching.replace(")?", "|)") # to avoid "unmatched group" error
        new_replacement = re.sub(r"\$(\d)", r"\\g<\1>", replacement)
        return new_matching, new_replacement

    def extract_rulesets(self, filename):
        tree = ET.parse(filename)
        root = tree.getroot()

        self.dict = {}
        for child in root:
            if child.tag == "ruleset":
                if "default_off" in child.attrib:
                    continue
                ruleset_name = child.attrib['name']
                ruleset = child.getchildren()
                self.dict[ruleset_name] = {}
                self.dict[ruleset_name]['targets'] = []
                self.dict[ruleset_name]['rules'] = []
                self.dict[ruleset_name]['exclusions'] = []
                for rule in ruleset:
                    if rule.tag == "target":
                        self.dict[ruleset_name]['targets'].append(rule.attrib['host'])
                    if rule.tag == "rule":
                        self.dict[ruleset_name]['rules'].append((rule.attrib['from'], rule.attrib['to']))
                    if rule.tag == "exclusion":
                        self.dict[ruleset_name]['exclusions'].append(rule.attrib['pattern'])

    def find(self, url):
        hostname_regex = r"https?://([^/]+)"
        try: #Remove
            host = re.findall(hostname_regex, url)[0]
        except IndexError, e:
            print url
            raise IndexError, e

        # In HTTPSEverywhere, URLs must contain a '/'.
        if url.replace("http://", "").find("/") == -1:
            url += "/"

        for ruleset in self.dict:
            for target in self.dict[ruleset]['targets']:
                if self.verify_target(target, host):
                    for exclusion in self.dict[ruleset]['exclusions']:
                        if re.findall(exclusion, url):
                            return None
                    for rule in self.dict[ruleset]['rules']:
                        matching_regex = rule[0] # "from"
                        replacement_regex = rule[1] # "to"
                        new_matching, new_replacement = self.convert_to_python(matching_regex, replacement_regex)
                        try:
                            replace_url = re.sub(new_matching, new_replacement, url)
                        except re.error, e:
                            print new_matching, new_replacement, url
                            raise re.error, e
                        if url != replace_url:
                            return replace_url
        return None

if __name__ == "__main__":
    import sys
    filename = sys.argv[1]
    url = sys.argv[2]
    script = FindRules(filename)
    replaced_url = script.find(url)
    print replaced_url
