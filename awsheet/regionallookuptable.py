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
    def __init__(self, configuration_yaml=None, configuration_directory=None, region_list=region_list):
        '''Parse the YAML in to the internal lookup table'''

        self.debug_mode = False
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        if configuration_yaml:
            self._lookup_table = configuration_yaml

        else:
            self._lookup_table = {}
            if configuration_directory is None:
                self.directory = os.path.dirname(os.path.realpath(sys.argv[0]))
            else:
                self.directory = configuration_directory
            for region_x in region_list:
                try:
                    with open('{}/{}.yaml'.format(self.directory, region_x)) as fp:
                        try:
                            self._lookup_table[region_x] = ruamel.yaml.load(fp, ruamel.yaml.RoundTripLoader)
                        except ParserError as err:
                            print "skipping region '{}': unparseable configuration".format(region_x)
                except IOError as err:
                    print "skipping region '{}': no configuration found in directory {}".format(region_x, self.directory)


    def lookup(self, region, key_path):
        if self.debug_mode:
            print "Looking up {} for {} region".format(key_path, region)
        full_key_path = key_path.split('.')
        full_key_path.insert(0, region)
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
