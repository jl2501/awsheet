import re
import os
import subprocess
import argparse
import sys
import logging
import atexit
import boto
import boto.ec2
import boto.ec2.elb
import collections

class AWSHeet:

    TAG = 'AWSHeet'

    def __init__(self, defaults={}, name=None):
        self.defaults = defaults
        self.resources = []
        self.parse_args()
        self.ec2_c = boto.ec2.connect_to_region(self.args.region)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        #handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.base_dir = os.path.dirname(os.path.realpath(sys.argv[0]))


        #- allow user to explicitly set project name
        default_base_name = os.path.basename(sys.argv[0]).split('.')[0]

        if name is None:
            self.base_name = default_base_name
        else:
            self.logger.info('Using parameter-based name override: {}'.format(name))
            self.base_name = name

        self.load_creds()

        #- resource reference table - this is used to refer to other resources by '@name'
        self.resource_refs = dict()

        #- If a resource needs some events to occur before it can fully converge then
        #- it must converge in 2 phases.
        #- In the second phase the resource can assume the resource reference table is complete

        #- It implements the second phase of convergence by declaring itself as a dependent resource
        #- Heet will register that resources converge_dependency() method to run at exit
        self.dependent_resources = dict()

        #- if we are run in destroy mode, do everything except call converge() on the resources
        #- in the resources list, then exit. At exit time, run this function.
        atexit.register(self._finalize)



    def load_creds(self):
        """Load credentials in preferred order 1) from x.auth file 2) from environmental vars or 3) from ~/.boto config"""

        user_boto_config = os.path.join(os.environ.get('HOME'), ".boto")
        self.parse_creds_from_file(user_boto_config)


        if os.getenv('AWS_ACCESS_KEY_ID', None) is not None:
            self.access_key_id = os.getenv('AWS_ACCESS_KEY_ID', None)
        if os.getenv('AWS_SECRET_ACCESS_KEY', None) is not None:
            self.secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY', None)

        auth_file = os.path.join(self.base_dir, self.base_name + ".auth")
        self.parse_creds_from_file(auth_file)

        self.logger.debug("using account AWS_ACCESS_KEY_ID=%s" % self.access_key_id)



    def parse_creds_from_file(self, filename):
        if not os.path.exists(filename):
            return
        with open(filename) as f:
            for line in f:
                match = re.match('^[^#]*AWS_ACCESS_KEY_ID\s*=\s*(\S+)', line, re.IGNORECASE)
                if match:
                    self.access_key_id = match.group(1)
                match = re.match('^[^#]*AWS_SECRET_ACCESS_KEY\s*=\s*(\S+)', line, re.IGNORECASE)
                if match:
                    self.secret_access_key = match.group(1)



    def is_resource_ref(self, ref_str):
        """Tests if ref_str is in a format that can be considered a resource reference
        Currently this format is not yet enforced anywhere."""
        if isinstance(ref_str, collections.Sequence) and ref_str[0] == '@':
            return True
        else:
            return False



    def add_resource_ref(self, resource, resource_ref_key):
        """Adds a resource to a dictionary so it can be referred to by a name / key
        Essentially the resource list, but without ordering constraints and with a requirement
        for random access of specific, named resources"""
        self.resource_refs[resource_ref_key] = resource



    def add_resource(self, resource):
        """Adds resources to a list and calls that resource's converge method"""
        self.resources.append(resource)
        if not self.args.destroy:
            #- catch exceptions in the converge() cycle
            #- to avoid calling the atexit functions
            #- when we are exiting because of an error
            try:
                resource.converge()
            except Exception as err:
                self.logger.error('Exception caught in converge cycle: {}'.format(str(err)))
                #- skip execution of registered atexit functions
                os._exit(os.EX_SOFTWARE)


        return resource



    def add_dependent_resource(self, dependent_resource, key_name):
        """Adds resources to a list and registers that resource's converge_dependency() method
        to be called at program exit and passes it the resource_name that it passed us.
        When a resource calls this, it also passes in a tag, used internally as a dict key, so that
        if a resource makes multiple calls to this, they can associate a string with each dependent
        event that they need to handle when the resource's converge_dependency() method is called back
        self.dependent_resources[key_name] = dependent_resource
        at program exit.

        Callbacks and tags are issued at exit in LIFO order."""
        atexit.register(dependent_resource.converge_dependency, key_name)
        return



    def _finalize(self):
        """Run this function automatically atexit. If --destroy flag is use, destroy all resouces in reverse order"""
        if not self.args.destroy:
            return
        sys.stdout.write("You have asked to destroy the following resources from [ %s / %s ]:\n\n" % (self.base_name, self.get_environment()))
        for resource in self.resources:
            print " * %s" % resource
        sys.stdout.write("\nAre you sure? y/N: ")
        choice = raw_input().lower()
        if choice != 'y':
            self.logger.warn("Abort - not destroying resources from [ %s / %s ] without affirmation" % (self.base_name, self.get_environment()))
            exit(1)
        for resource in reversed(self.resources):
            resource.destroy()
        self.logger.info("all AWS resources in [ %s / %s ] have had destroy() called" % (self.base_name, self.get_environment()))



    def parse_args(self):
        parser = argparse.ArgumentParser(description='create and destroy AWS resources idempotently')
        parser.add_argument('-d', '--destroy', help='release the resources (terminate instances, delete stacks, etc)', action='store_true')
        parser.add_argument('-e', '--environment', help='e.g. production, staging, testing, etc', default='testing')
        parser.add_argument('-r', '--region', help='region name to connect to', default='us-east-1')
        parser.add_argument('-v', '--version', help='create/destroy resources associated with a version to support '
                                                    'having multiple versions of resources running at the same time. '
                                                    'Some resources are not possibly able to support versions - '
                                                    'such as CNAMEs without a version string.')
        #- TODO: to support this 'dry_run' feature request, we will add
        #-     a wrapper library for all the boto stuff and import boto through that abstraction
        #-     all the boto stuff that would write something will then be placed in a sub-layer of the
        #-     overall boto abstraction that doesn't run in dry_run mode
        #-     (when some lookupable way to access the value
        #-     that is set here in some kind of "mode configuration" object says that we are in 'dry_run' mode.
        #-      (configuration object in C would be bitmask of logical OR flags kind of data structure / an object with
        #-      a bunch of bool-like attributes for each mode...))
        #parser.add_argument('-n', '--dry-run', help='environment', action='store_true')
        self.args = parser.parse_args()



    def get_region(self):
        return self.get_value('region', default='us-east-1')

    def get_project(self):
        return self.base_name

    def get_version(self):
        return self.args.version if self.args.version else 0

    def get_environment(self):
        return self.args.environment

    def get_destroy(self):
        return self.args.destroy



    def get_value(self, name, kwargs={}, default='__unspecified__', required=False):
        """return first existing value from 1) kwargs dict params 2) global heet defaults 3) default param or 4) return None"""
        if (name in kwargs):
            return kwargs[name]
        if (name in self.defaults):
            return self.defaults[name]
        if (default != '__unspecified__'):
            return default
        if required:
            raise Exception("You are missing a required argument or default value for '%s'." % (name))
        return None



    def exec_awscli(self, cmd):
        init_env = os.environ.copy()
        env = dict()

        #- strip the environment of non utf-8 encodable characters or Popen will fail
        for key_x, value_x in init_env.iteritems():
            key_y = value_y = ''
            try:
                key_y = str(key_x).encode('utf-8', 'replace')
                value_y = str(value_x).encode('utf-8', 'replace')
            except UnicodeDecodeError as err:
                print "removing environment setting {} from passed env due to Unicode Error.({})".format(key_x, value_x)
                key_y = value_y = ''
            env[key_y] = value_y

        env['AWS_ACCESS_KEY_ID'] = self.access_key_id.encode('utf-8')
        env['AWS_SECRET_ACCESS_KEY'] = self.secret_access_key.encode('utf-8')

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, env=env)
        return proc.communicate()[0]



    def add_instance_to_elb(self, defaults, elb_name, instance_helper):
        #-TODO: move this to Load Balancer Helper type when ELBHelper is implemented
        if self.args.destroy:
            return
        conn = boto.ec2.elb.connect_to_region(
            self.get_region(),
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key)
        lb = conn.get_all_load_balancers(load_balancer_names=[elb_name])[0]
        instance_id = instance_helper.get_instance().id
        self.logger.info("register instance %s on %s" % (instance_id, elb_name))
        lb.register_instances(instance_id)
