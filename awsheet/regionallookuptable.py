"""This module contains the code to look up per-region specific values that are needed when coding for Cloud Formation and AWSHeet
The YAML file parses into a dictionary, and we wrap that in an object because a YAML-based dictionary implementation is likely to change
in the future as the code is iteratively changed """


import os
import ruamel.yaml
import logging
import sys
from ruamel.yaml.parser import ParserError

region_list = [
        'ap-northeast-1',
        'ap-southeast-1',
        'ap-southeast-2',
        'eu-central-1',
        'eu-west-1',
        'sa-east-1',
        'us-east-1',
        'us-west-1',
        'us-west-2']

class RegionalLookupTable(object):
    def __init__(self, region_name, configuration_yaml=None, configuration_directory='./regional_constants'):
        '''Parse the YAML in to the internal lookup table'''

        self.debug_mode = False
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.region_name = region_name

        if configuration_yaml:
            self._lookup_table = configuration_yaml

        else:
            self._lookup_table = {}
            if configuration_directory is None:
                self.directory = os.path.dirname(os.path.realpath(sys.argv[0]))
            else:
                self.directory = configuration_directory
            try:
                with open('{}/{}.yaml'.format(self.directory, self.region_name)) as fp:
                    try:
                        self._lookup_table = ruamel.yaml.load(fp, ruamel.yaml.RoundTripLoader)
                    except ParserError as err:
                        print "'{}': unparseable region configuration".format(self.region_name)
            except IOError as err:
                print "region '{}': no configuration found in directory {}".format(self.region_name, self.directory)


    def lookup(self, key_path):
        if self.debug_mode:
            print "Looking up {} for {} region".format(key_path, self.region_name)
        full_key_path = key_path.split('.')
        if self.debug_mode:
            print "len(full_key_path): {}({})".format(len(full_key_path), str(full_key_path))

        value = None
        lookup_table = self._lookup_table
        for key_x in full_key_path:
            try:
                lookup_table = lookup_table[key_x]

            except KeyError as err:
                print "No Data Exists for '{}'".format(str(key_path))
                raise(err)

        final_value = lookup_table
        return final_value
