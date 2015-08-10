"""This module contains the code to look up per-region specific values that are needed when coding for Cloud Formation and AWSHeet
The YAML file parses into a dictionary, and we wrap that in an object because a YAML-based dictionary implementation is likely to change
in the future as the code is iteratively changed """


import os
import ruamel.yaml

CONFIGURATION_DIRECTORY='.'
CONFIGURATION_FILENAME='regional_constants.yaml'


class RegionalLookupTable(object):
    def __init__(self, configuration_yaml=None, configuration_directory=CONFIGURATION_DIRECTORY, configuration_filename=CONFIGURATION_FILENAME):
        '''Parse the YAML in to the internal lookup table'''

        self.debug_mode = False
        config_file_path = os.path.join(configuration_directory, configuration_filename)
        config_file_path = os.path.expandvars(config_file_path)
        config_file_path = os.path.expanduser(config_file_path)
        config_file_path = os.path.realpath(config_file_path)

        with open(config_file_path) as fp:
            self._lookup_table = ruamel.yaml.load(fp, ruamel.yaml.RoundTripLoader)


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
