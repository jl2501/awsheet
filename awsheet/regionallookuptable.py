"""This module contains the code to look up per-region specific values that are needed when coding for Cloud Formation and AWSHeet
The YAML file parses into a dictionary, and we wrap that in an object because a YAML-based dictionary implementation is likely to change
in the future as the code is iteratively changed """


import os
import ruamel.yaml

CONFIGURATION_DIRECTORY='.'
CONFIGURATION_FILENAME='regional_constants.yaml'


class RegionalLookupTable(object):
    def __init__(self, configuration_yaml=None, configuration_directory=CONFIGURATION_DIRECTORYe, configuration_filename=CONFIGURATION_FILENAME):
        '''Parse the YAML in to the internal lookup table'''

        config_file_path = os.path.join(configuration_irectory, configuration_filename)
        config_file_path = os.path.expandvars(config_file_path)
        config_file_path = os.path.expanduser(config_file_path)
        config_file_path = os.path.realpath(config_file_path)

        with fp as open(config_file_path):
            self.lookup_table = ruamel.yaml.load(fp, ruamel.yaml.RoundTripLoader)


    def lookup_by_region(region, key_path):
        full_key_path = [region]
        full_key_path.extend(key_path)

        value = None
        for key_x in key_path:
            try:
                value = self.lookup_table[key_x]
            except KeyError:
                value = None
                break

            return value
