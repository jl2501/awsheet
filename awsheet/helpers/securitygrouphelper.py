from .awshelper import AWSHelper
import time
import re
import os
import json
import subprocess
import tempfile
import argparse
import sys
import logging
import atexit
import boto
import boto.ec2
import boto.ec2.elb
import boto.cloudformation
import collections
import ipaddress
import boto.exception

#TODO: IMPLEMENT TAGGING

#- no need for a full class. These are simple tuples
#- TODO: actually having rules as immutables makes normalization more complex.
#-       refactor this particular tuple into its own class and define rules of
#-       interaction between security groups and rules they contain
#-       as rules themselves do need access to the heet object and to the boto_sg
#-       to perform some aspects of normalization
SecurityGroupRule = collections.namedtuple('SecurityGroupRule', ['ip_protocol', 'from_port', 'to_port', 'cidr_ip', 'src_group'])

#- rm_group: only try to delete the group, fail if the API call fails
#- rm_instances: delete all the instances in this group before attempting deletion of this security group
#- rm_enis: delete all of the Elastic Network Interfaces in this security group before attempting deletion of this security group 
SecurityGroupDeleteMode = collections.namedtuple('SecurityGroupDeleteMode', ['rm_group', 'rm_instances', 'rm_enis'])


#- this defines the identity of the security group to Heet Code
#- as long as none of these change, we will converge the same AWS resource
#-     VPC ID
#-     Heet Project Name (Base Name / the name of the script)
#-     Heet Environment (usually, testing, staging or production)
#-     Security Group Name
SgTag = collections.namedtuple('SecurityGroupIDTag',[ 'environment', 'project_name', 'vpc_id', 'sg_name'])



class SecurityGroupHelper(AWSHelper):
    """modular and convergent security groups in VPC (and only in VPC)
    Params"""

    def __init__(self, heet, base_name, description, rules=None, vpc_id=None, rm_group=True, rm_instances=False, rm_enis=False):
        self.heet = heet
        self.base_name = base_name
        self.description = description
        self.aws_name = self.build_aws_name(self.base_name)
        self.region = self.heet.get_region()
        self.vpc_id = self.heet.get_value('vpc_id', required=True)
        self._resource_object = None
        self.delete_modes = SecurityGroupDeleteMode(rm_group, rm_instances, rm_enis)

        #- helps to know how many we have done, how many left
        self._num_converged_dependencies = 0

        #- these are actually dependent on the above working
        self.heet_id_tag = self.build_heet_id_tag()

        self.conn = boto.ec2.connect_to_region(
            self.region,
            aws_access_key_id=heet.access_key_id,
            aws_secret_access_key=heet.secret_access_key)

        #- when we create a rule that references another group
        #- we have to check that group exists
        #- so, when we do that check, we cache the resulting objects
        #- here. Saves extra calls to the API, which can be throttled.
        self.src_group_references = dict()

        self.rules = set()

        #- this is where we put the rules that refer to other AWSHeet SGs that are also declared
        #- in this same module. Dict Key for each is the rule's src_group attribute
        self.dependent_rules = dict()

        #- this will actually make API calls
        #- to get the source group reference objects
        if rules is not None:
            for rule in rules:
                self.add_rule(rule)


        self.heet.logger.debug('^^^ SGH init: [{}]'.format(self.base_name))
        #- Post Init Hook
        self.post_init_hook()

        #- add ourselves to the heet dict so we are reachable by an '@' reference
        heet.add_resource_ref(self, self.base_name_to_ref(self.base_name))

        # this will callback the new instance's securitygrouphelper.converge()
        heet.add_resource(self)




    def __str__(self):
        return "SecurityGroup %s" % self.aws_name



    def post_converge_hook(self):
        print "----POST CONVERGE HOOK----"



    def normalize_aws_sg_rules(self, aws_sg):
        """AWS has grants and rules, but we work with them as a logical unit.
        The rules have the ip_protocol, from_port, to_port while the grants have the remaining parameters,
        which are the mutually exclusive group_id or cidr_ip parameters
        Also normalize sg-ids that are references to 'self'
        and convert the security group IDs to resource references for SGs in this module"""

        boto_self = self.get_or_create_resource_object()
        normalized_rules = set()
        if aws_sg is not None:
            for rule in aws_sg.rules:
                for grant in rule.grants:
                    #- group-based rules are special as they may represent 'self'
                    normalized_group_id = grant.group_id
                    #- check for self
                    if grant.group_id is not None and grant.group_id == boto_self.id:
                        self.heet.logger.debug('Normalizing security group ID reference to self')
                        normalized_group_id = 'self'

                    rule = SecurityGroupRule(rule.ip_protocol, rule.from_port, rule.to_port, grant.cidr_ip, normalized_group_id)

                    #- be sure that we are always comparing similarly normalized rules 
                    #- apply self.normalize_rule to API returned rules as well
                    normalized_rules.add(self.normalize_rule(rule))
                
            return normalized_rules



    def get_resource_object(self):
        """Get or create the Boto Version of this security group from EC2 via API"""

        #- build the tag and find it by tag
        (tag_name, tag_value) = self.heet_id_tag
        matching_groups = self.conn.get_all_security_groups(filters={'tag-key' : tag_name, 'tag-value' :tag_value})

        boto_group = None
        if matching_groups:
            #- if there's more than one security group in the same project and environment with the same name,
            #- this is worthy of logging an error as it isn't expected
            if len(matching_groups) > 1:
                self.heet.logger.warn("multiple security groups returned!: search tag:[{}: {}]".format(tag_name, tag_value))
            boto_group = matching_groups[0]
        return boto_group



    def get_or_create_resource_object(self):
        """Get or create the Boto Version of this security group from EC2 via API"""

        (tag_name, tag_value) = self.heet_id_tag
        boto_group = self.get_resource_object()
        if not boto_group:
            #- it doesn't exist yet
            try:
                boto_group = self.conn.create_security_group(name=self.aws_name, description=self.description, vpc_id=self.vpc_id)
                boto_group.add_tag(key=tag_name, value=tag_value)
            except boto.exception.EC2ResponseError as err:
                print 'AWS EC2 API error: {}'.format(err.message)
                return None

        return boto_group




    def make_key_from_rule(self, rule):
        """Just join all the things together to make a unique string"""
        key = '/'.join([str(rule.ip_protocol), str(rule.from_port), str(rule.to_port), str(rule.cidr_ip), str(rule.src_group)])
        return key



    def rule_fails_check(self, rule):
        """Checks that the rule has all the needed attributes
        Returns a list of strings with error messages for each test the rule failed.
        If it passes, then the list will be empty.
        As well, this populates self.src_group_references dict"""

        #- a list of all the ways that the rule has failed
        rule_status = []

        if str(rule.ip_protocol) not in ['tcp','udp', 'icmp', '-1']:
            rule_status.append('bad value for ip_protocol in rule {}'.format(str(rule)))

        #- try to convert to float to check if it is a valid port number
        try:
            if rule.from_port < 0 and rule.from_port != -1:
                rule_status.append('rule from_port is a negative number that is not -1')
                raise TypeError()
            float(rule.from_port)

        except TypeError as err:
            if rule.from_port is None:
                pass
            else:
                rule_status.append('rule from port is not a valid integer')

        try:
            if rule.to_port < 0 and rule.to_port != -1:
                rule_status.append('rule to_port is a negative number that is not -1')
                raise TypeError()
            float(rule.to_port)

        except TypeError as err:
            if rule.to_port is None:
                pass
            else:
                rule_status.append('rule to port is not a valid integer')

        #- Check the (.cidr_ip, .src_group) pair compliance
        #- need to have exactly one of src_group, cidr_ip
        if rule.cidr_ip is not None:
            self.heet.logger.debug(' ^^^ rule has cidr_ip')
            if rule.src_group is not None:
                self.heet.logger.debug(' ^^^ rule has both cidr_ip and src_group')
                rule_status.append('Can\'t have both cidr_ip and src_group set simultaneously: rule {}'.format(str(rule)))

            else:
                self.heet.logger.debug(' ^^^ rule has only cidr_ip')
                #- test the cidr_ip
                try:
                    ipaddress.IPv4Network(unicode(rule.cidr_ip))
                except ValueError as err:
                    self.heet.logger.debug(' ^^^ rule has invalid cidr_ip')
                    rule_status.append('rule has an invalid cidr_ip value')

        elif rule.cidr_ip is None and rule.src_group is None:
            self.heet.logger.debug(' ^^^ rule has neither cidr_ip nor src_group')
            rule_status.append('Must specify one or other of [cidr_ip, src_group]')
               
        else:
            if rule.src_group == 'self':
                self.heet.logger.debug(' ^^^ rule src_group refers to "self"')
                boto_self = self.get_or_create_resource_object()
                self.src_group_references[boto_self.id] = boto_self
            elif rule.src_group != 'self' and not self.rule_has_dependent_reference(rule):
                self.heet.logger.debug('^^^ rule that references AWS SG directly: {}'.format(rule.src_group))
                #- get the boto object for the reference security group so we
                #- can pass that object into boto's authorize() method
                src_group_resource = self.conn.get_all_security_groups(group_ids=rule.src_group)
                if len(src_group_resource) <= 0:
                    self.heet.logger.debug('^^^ rule references another security group ID [{}] that doesn\'t exist'.format(rule.src_group))
                    rule_status.append('References another security group ID [{}] that doesn\'t exist'.format(rule.src_group))
                else:
                    self.heet.logger.debug('added src_group_references[{}]'.format(rule.src_group))
                    self.src_group_references[rule.src_group] = src_group_resource[0]
            elif self.heet.is_resource_ref(rule.src_group):
                #- this is a reference to another heet security group helper object
                #- we should make sure that this actually exists before saying its okay
                #- but we can only do that after we have a comprehensive list of all the
                #- security groups to be created, which we will only have at the end of the
                #- program.
                #- So here, we add this name to a list of things which will be done at exit.
                self.heet.logger.debug('^^^ rule seems to be a new style resource reference.')
                key = self.make_key_from_rule(rule)
                self.heet.add_dependent_resource(self, key)
                self.dependent_rules[key] = rule

        return rule_status



    def is_aws_reference(self, src_group):
        """Check if the src_group argument looks like an AWS security group ID
        Just means the first three characters are 'sg-'"""

        is_ref = False
        if src_group[0] == 's' and src_group[1] == 'g' and src_group[2] == '-' and len(src_group.split('-')) == 2:
            is_ref = True

        return is_ref



    def normalize_rule(self, rule):
        """Normalize SecurityGroupRule attributes that can have multiple values representing the same thing into one well-defined value
        Currently only checks from_port and to_port for '-1' or None and normalizes them to be None as that's what the API returns"""

        #- make a mutable copy
        new_rule = {'ip_protocol' : rule.ip_protocol, 
                'from_port' : rule.from_port,
                'to_port' : rule.to_port,
                'cidr_ip' : rule.cidr_ip,
                'src_group' : rule.src_group }

        #- just go through and normalize all the values one by one and make a new rule at the end
        #- out of all the stuff we collect throughout the normalization tests
        if new_rule['src_group'] == 'self':
            new_rule['src_group'] = self.get_or_create_resource_object().id

        if self.heet.is_resource_ref(new_rule['src_group']):
            try:
                #- try to look it up
                self.heet.logger.debug('Normalizing resource_reference: {}'.format(rule.src_group))
                boto_sg = self.heet.resource_refs[new_rule['src_group']].get_resource_object()
                if boto_sg:
                    new_rule['src_group'] = boto_sg.id

            except KeyError as err:
                #- it wasn't in the reference table yet, 
                #- we'll handle this in converge() and converge_dependency() 
                pass

        if rule.ip_protocol == -1:
            self.heet.logger.debug('Normalizing ip_protocol: {}'.format(rule.ip_protocol))
            new_rule['ip_protocol'] = '-1'

        #- we check for None explicitly also to short-circuit else the int() will fail w/ TypeError and we want it to pass
        if new_rule['from_port'] is None or new_rule['to_port'] is None or int(new_rule['from_port']) == -1 or int(new_rule['to_port']) == -1:
            self.heet.logger.debug('Normalizing port range: {} .. {}'.format(rule.from_port, rule.to_port))
            new_rule['from_port'] = None
            new_rule['to_port'] = None

        
        final_rule = SecurityGroupRule(new_rule['ip_protocol'], new_rule['from_port'], new_rule['to_port'], new_rule['cidr_ip'], new_rule['src_group'])
        return final_rule



    def add_rule(self, rule):
        """Print out why a rule fails to be added, else add a rule to this security group
        Rule will be normalized and added to one of two lists of rules:
            One group is for rules that can be converged immediately
            (those ones have no src_group resource references)
            The other group is for rules that will be converged after the resource
            reference table has been built
        """
        failures = self.rule_fails_check(rule)
        if not failures:
            normalized_rule = self.normalize_rule(rule)
            self.rules.add(normalized_rule)
        else:
            for err in failures:
                self.heet.logger.error('Security Group failed sanity checks: ')
                self.heet.logger.error('    : ' + err)
        return



    def build_heet_id_tag(self):
        """The tag is what defines a security group as a unique component of heet code
        This format has the following consequences:
            * you can change the id of a security group and still converge
            * you can not converge across projects, environments or sgs with different names, or different VPCs
            * you can change the rules of an SG and converge"""

        sg_tag = SgTag(self.heet.get_environment(), self.heet.base_name, self.vpc_id, self.aws_name)
        tag_value = ':'.join(sg_tag)
        tag_name = 'heet_id'

        return (tag_name, tag_value)



    def build_aws_name(self, base_name):
        """The name of the security group is basically the Tag concatenated in order, minus the vpc id
        NB: AWS only determines SG uniqueness by (VPC_ID, SG Name), so if you want the same code for different environments,
        you have to add some additional environment-specific info to the name"""
        return '-'.join([self.heet.get_environment(), self.heet.base_name, base_name])



    def rule_has_dependent_reference(self, rule):
        """Check if the rule refers to a security group that is another Heet object
        For now, we do that by passing in the heet base_name of the group prefixed with an '@'"""
        return self.heet.is_resource_ref(rule.src_group)



    def base_name_to_ref(self, base_name):
        """Converts the Heet Script's SG base name into a name reference.
        Currently, this just means that it is prepended with an '@'"""
        return '@' + base_name



    def ref_to_base_name(self,base_name):
        """The opposite of the above."""
        if base_name[0] == '@':
            return base_name[1:]
        else:
            self.heet.logger.error("Trying to dereference a SG name that isn't a reference: {}".format(base_name))
            return None



    def converge(self):
        """Adds missing rules, revokes extra rules, creates entire group if necessary
        if the rule can't be converged yet (due to an unresolveable resource reference, 
        we'll let heet know to call us at the module exit time and re-try via converge_dependency()
        when we have the full module resource reference table"""

        self.heet.logger.info("Converging security group: %s" % self.aws_name)

        boto_self = self.get_resource_object()
        if boto_self is None:
            self.heet.logger.debug("Creating new group: %s" % self.aws_name)
            boto_self = self.conn.create_security_group(self.aws_name, self.description, self.vpc_id)
            #- wait for API consistency - sleep momentarily before adding tag
            time.sleep(0.25)
            (tag_name,tag_value) = self.heet_id_tag
            boto_self.add_tag(key=tag_name, value=tag_value)
            remote_rules = set()
        else:
            self.heet.logger.debug("Using pre-existing group: %s" % self.aws_name)
            remote_rules = set(self.normalize_aws_sg_rules(boto_self))

        self.src_group_references['self'] = boto_self
        self.src_group_references[boto_self.id] = boto_self

        if self.rules:
            desired_rules = set(self.rules)
        else:
            desired_rules = set()

        #print "DEBUG : remote rules: {}".format(remote_rules)
        #print "DEBUG : desired rules: {}".format(desired_rules)

        for rule in desired_rules:
            #- if it isn't there, add it
            if rule in remote_rules:
                self.heet.logger.info("Already Authorized: %s on %s" % (rule, self))
            else:
                if rule.src_group:
                    #- check if this rule can be converged now or later
                    if self.rule_has_dependent_reference(rule):
                        self.heet.logger.debug("-- Rule refers to another Heet group. Will converge_dependency() atexit: {}".format(rule))
                        key = self.make_key_from_rule(rule)
                        self.heet.add_dependent_resource(self, key)
                        self.dependent_rules[key] = rule
                    elif self.is_aws_reference(rule.src_group):
                        #- use the src_group object we already got when we checked the rule
                        self.heet.logger.info("Adding Authorization: %s on %s" % (rule, self))
                        boto_self.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip, self.src_group_references[rule.src_group])
                    else:
                        print "Unexpected Rule format: {}".format(rule)
                        raise AttributeError('Source Group reference can NOT be converged')
                else:
                    boto_self.authorize(rule.ip_protocol,rule.from_port, rule.to_port,rule.cidr_ip)

        #- remove all the rules that we didn't explicitly declare we want in this group
        for rule in remote_rules:
            if rule not in desired_rules:
                self.heet.logger.info("Removing remote rule not declared locally: {} in {}".format(rule, self))

                #- boto-specific: get the referring security group boto-level object to delete this rule
                ref_sg = None
                if rule.src_group is not None:
                    if rule.src_group == 'self':
                        ref_sg = [self.get_or_create_resource_object()]
                    elif self.is_aws_reference(rule.src_group):
                        ref_sg = self.conn.get_all_security_groups(group_ids=rule.src_group)
                        if len(ref_sg) >= 1:
                            ref_sg = ref_sg[0]
                        else:
                            self.heet.logger.error("Rule to delete references another Security Group that no longer exists. Will fail...")
                            reg_sg = None
                if ref_sg is None:
                    key = self.make_key_from_rule(rule)
                    self.heet.add_dependent_resource(self, key)
                    self.dependent_rules[key] = rule
                else:
                    boto_self.revoke(rule.ip_protocol, rule.from_port, rule.to_port, rule.cidr_ip, ref_sg)

        #- Post Converge Hook
        self.post_converge_hook()



    def converge_dependency(self, name):
        """This is where we converge the rules that refer to other security groups that are declared in the same AWSHeet module
        Dependencies here is any security group rule that referenced another Heet group that is being declared in this script.
        If it is the first time the group is created, the referenced group will not exist yet, and so the rule will fail convergence.
        So, to keep it simple, any group that refers to another group in a Heet script will be put off to be converged after we are 
        sure that the creation of the rule should not fail unless there has been an actual error."""
        #- TODO: this should have a revoke cycle as well. rules that refer to other groups can't be verified until all we have resolved
        #- all of the security group ids to resource references

        if self.heet.args.destroy:
            return

        print ""
        print "----CONVERGE_DEPENDENCY() {}: {}---- {} of {} rules to process".format(self.base_name, name, self._num_converged_dependencies+1, len(self.dependent_rules))
        #print ""
        self._num_converged_dependencies += 1

        boto_self_sg = self.get_or_create_resource_object()

        #- lookup the rule as it was when we saved it
        init_rule = self.dependent_rules[name]

        #- grab the group we need from the resource references
        resource_name = name.split('/')[-1]
        boto_src_group = self.heet.resource_refs[resource_name].get_or_create_resource_object()

        #- TODO: clean this up
        #- we need the ID for comparisons, but we need the object for the API call
        #- and we start with a resource reference
        new_rule = SecurityGroupRule(init_rule.ip_protocol, 
                                     init_rule.from_port, 
                                     init_rule.to_port, 
                                     init_rule.cidr_ip, 
                                     boto_src_group.id)

        normalized_rule = self.normalize_rule(new_rule)

        final_rule = SecurityGroupRule(normalized_rule.ip_protocol, 
                                       normalized_rule.from_port, 
                                       normalized_rule.to_port, 
                                       normalized_rule.cidr_ip, 
                                       boto_src_group)


        remote_rules = self.normalize_aws_sg_rules(boto_self)

        #print "                     ----------------------------------- "
        #print "                    |                                   |"
        #print "                    |              debug_start          |"
        #print "                    |                                   |"
        #print "                     ----------------------------------- "
        #print "________________________________________________________________________________"
        #print "REMOTE RULES:"
        #for rule in remote_rules:
        #    print rule
        #print "________________________________________________________________________________"
        if normalized_rule not in remote_rules:
        #    print "CURRENT RULE:"
        #    print normalized_rule
        #    print "    Not found in: "
        #    print " _______________________________________________________________________________"
        #    print "|_______________________________________________________________________________|"
            boto_self.authorize(final_rule.ip_protocol, final_rule.from_port, final_rule.to_port, final_rule.cidr_ip, final_rule.src_group)
            time.sleep(0.25)

        #-TODO: go through and revoke extra rules



    def destroy(self):
        boto_self = self.get_resource_object()

        if not boto_self:
            return

        #- Pre Destroy Hook
        self.pre_destroy_hook()

        self.heet.logger.info("deleting SecurityGroup record %s" % (self.aws_name))
        #- first delete any src_group rules so the group can be deleted
        for boto_rule in boto_self.rules:
            for boto_grant in boto_rule.grants:
                #print " *** DEBUG: boto_rule: boto_grant :: [{}] : [{}]".format(boto_rule, boto_grant)
                if boto_grant.group_id is not None:
                    try:
                        src_group_ref = self.conn.get_all_security_groups(group_ids=[boto_grant.group_id])[0]
                        self.heet.logger.debug('Removing rule with src_group to remove group.({}:{})'.format(boto_grant.group_id, src_group_ref.name))
                        boto_self.revoke(boto_rule.ip_protocol, boto_rule.from_port, boto_rule.to_port, boto_grant.cidr_ip, src_group_ref)
                    except boto.exception.EC2ResponseError as err:
                        self.heet.logger.debug('Failed to remove rule: [{}]'.format(err.message))
                    except KeyError as err:
                        print "FAILED KEY IN SRC_GROUP_REFERENCES: {}".format(boto_grant.group_id)
                        print " CURRENT SRC_GROUP_REFERENCES:"
                        print "        {}".format(self.src_group_references)
                        print " ------XXX------ "

        try:
            boto_self.delete()
            self.heet.logger.info('Successfully deleted group {}.'.format(self.aws_name))
        except boto.exception.EC2ResponseError as err:
            # 
            self.heet.logger.info("*** Unable to delete {}. {}".format(self.aws_name, err.message))
            time.sleep(3)

        return
