
class AWSHeet:

    TAG = 'AWSHeet'

    def __init__(self, defaults={}):
        self.defaults = defaults
        self.resources = []
        self.parse_args()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        #handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.base_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.base_name = re.search('(.*)\.[^\.]*$', os.path.basename(sys.argv[0])).group(1)
        self.load_creds()
        atexit.register(self._finalize)

    def load_creds(self):
        """Load credentials in preferred order 1) from x.auth file 2) from environmental vars or 3) from ~/.boto config"""

        user_boto_config = os.path.join(os.environ.get('HOME'), ".boto")
        self.parse_creds_from_file(user_boto_config)

        self.access_key_id = os.getenv('AWS_ACCESS_KEY_ID', None)
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

    def add_resource(self, resource):
        self.resources.append(resource)
        if not self.args.destroy:
            resource.converge()
        return resource

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
        self.logger.info("all AWS resources in [ %s / %s ] are destroyed" % (self.base_name, self.get_environment()))

    def parse_args(self):
        parser = argparse.ArgumentParser(description='create and destroy AWS resources idempotently')
        parser.add_argument('-d', '--destroy', help='release the resources (terminate instances, delete stacks, etc)', action='store_true')
        parser.add_argument('-e', '--environment', help='e.g. production, staging, testing, etc', default='testing')
        parser.add_argument('-v', '--version', help='create/destroy resources associated with a version to support having multiple versions of resources running at the same time. Some resources are not possibly able to support versions - such as CNAMEs without a version string.')
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
        env = os.environ.copy()
        env['AWS_ACCESS_KEY_ID'] = self.access_key_id
        env['AWS_SECRET_ACCESS_KEY'] = self.secret_access_key
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, env=env)
        return proc.communicate()[0]

    def add_instance_to_elb(self, defaults, elb_name, instance_helper):
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
