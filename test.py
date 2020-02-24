#Author: David Lozano

import boto3
import json
import re
import logging
import time
import uuid
import random
from datetime import datetime

logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',level=logging.INFO)


# def is_valid_hostname(hostname):
#     """This function checks to see whether the hostname entered into the zone and cname tags is a valid hostname."""
#     if hostname is None or len(hostname) > 255:
#         return False
#     if hostname[-1] == ".":
#         hostname = hostname[:-1]
#     allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
#     return all(allowed.match(x) for x in hostname.split("."))


#---------------------------------------------------------------------------------------------------------------------------------------------------

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")

def create_table(table_name):
    dynamodb_client.create_table(
            TableName=table_name,
            AttributeDefinitions=[
                {
                    'AttributeName': 'InstanceId',
                    'AttributeType': 'S'
                },
            ],
            KeySchema=[
                {
                    'AttributeName': 'InstanceId',
                    'KeyType': 'HASH'
                },
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 4,
                'WriteCapacityUnits': 4
            }
        )
    table = dynamodb_resource.Table(table_name)
    table.wait_until_exists()

def get_dhcp_configurations(dhcp_options_id):
    """This function returns the name of the first zone/domain that is in the option set."""
    dhcp_options = ec2.DhcpOptions(dhcp_options_id)
    dhcp_configurations = dhcp_options.dhcp_configurations
    domain_name = dhcp_configurations[0]['Values'][0]['Value']
    return domain_name + '.'

def is_dns_hostnames_enabled(vpc):
    dns_hostnames_enabled = vpc.describe_attribute(
    DryRun=False,
    Attribute='enableDnsHostnames'
)
    return dns_hostnames_enabled['EnableDnsHostnames']['Value']

def is_dns_support_enabled(vpc):
    dns_support_enabled = vpc.describe_attribute(
    DryRun=False,
    Attribute='enableDnsSupport'
)
    return dns_support_enabled['EnableDnsSupport']['Value']

def remove_empty_from_dict(d):
    """Removes empty keys from dictionary"""
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d

def get_reversed_domain_prefix(subnet_mask, private_ip):
    """Uses the mask to get the zone prefix for the reverse lookup zone"""
    if 32 >= subnet_mask >= 24:
        third_octet = re.search('\d{1,3}.\d{1,3}.\d{1,3}.',private_ip)
        return third_octet.group(0)
    elif 24 > subnet_mask >= 16:
        second_octet = re.search('\d{1,3}.\d{1,3}.', private_ip)
        return second_octet.group(0)
    else:
        first_octet = re.search('\d{1,3}.', private_ip)
        return first_octet.group(0)

def reverse_list(list):
    """Reverses the order of the instance's IP address and helps construct the reverse lookup zone name."""
    if (re.search('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',list)) or (re.search('\d{1,3}.\d{1,3}.\d{1,3}\.',list)) or (re.search('\d{1,3}.\d{1,3}\.',list)) or (re.search('\d{1,3}\.',list)):
        list = str.split(str(list),'.')
        list = [_f for _f in list if _f]
        list.reverse()
        reversed_list = ''
        for item in list:
            reversed_list = reversed_list + item + '.'
        return reversed_list
    else:
        print('Not a valid ip')
        exit()

def get_hosted_zone_properties(zone_id):
    hosted_zone_properties = route53.get_hosted_zone(Id=zone_id)
    hosted_zone_properties.pop('ResponseMetadata')
    return hosted_zone_properties

def associate_zone(hosted_zone_id, region, vpc_id):
    """Associates private hosted zone with VPC"""
    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=hosted_zone_id,
        VPC={
            'VPCRegion': region,
            'VPCId': vpc_id
        },
        Comment='Updated by Lambda DDNS'
    )

def get_zone_id(zone_name):
    """This function returns the zone id for the zone name that's passed into the function."""
    if zone_name[-1] != '.':
        zone_name = zone_name + '.'
    hosted_zones = route53.list_hosted_zones()
    x = [record for record in hosted_zones['HostedZones'] if record['Name'] == zone_name]
    try:
        zone_id_long = x[0]['Id']
        zone_id = str.split(str(zone_id_long),'/')[2]
        return zone_id
    except:
        return None

def create_reverse_lookup_zone(instance, reversed_lookup_zone, region):
    """Creates the reverse lookup zone."""
    print('Creating reverse lookup zone %s' % reversed_lookup_zone)
    route53.create_hosted_zone(
        Name = reversed_lookup_zone,
        VPC = {
            'VPCRegion':region,
            'VPCId': instance['Reservations'][0]['Instances'][0]['VpcId']
        },
        CallerReference=str(uuid.uuid1()),
        HostedZoneConfig={
            'Comment': 'Updated by Lambda DDNS',
        },
    )

def create_resource_record(zone_id, record_name, type, value):
    """This function creates resource records in the hosted zone passed by the calling function."""
    print('Updating %s record %s in zone %s ' % (type, record_name, get_hosted_zone_properties(zone_id)['HostedZone']['Name']))
    if record_name[-1] != '.':
        record_name = record_name + '.'
    route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": record_name,
                                "Type": type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {
                                        "Value": value
                                    },
                                ]
                            }
                        },
                    ]
                }
            )

def delete_resource_record(zone_id, record_name, type, value):
    """This function deletes resource records from the hosted zone passed by the calling function."""
    print('Deleting %s record %s in zone' % (type, record_name))
    if record_name[-1] != '.':
        record_name = record_name + '.'
    route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": record_name,
                                "Type": type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {
                                        "Value": value
                                    },
                                ]
                            }
                        },
                    ]
                }
            )

f = open('event_sample.json')
event = json.load(f)

#boto3 resources
route53 = boto3.client('route53')
ec2 = boto3.resource('ec2')
compute = boto3.client('ec2')
dynamodb_client = boto3.client('dynamodb')
dynamodb_resource = boto3.resource('dynamodb')

#get data from the event
state = event['detail']['state']
instance_id = event['detail']['instance-id']
region = event['region']
table = dynamodb_resource.Table('DDNS')
f.close()

logging.info('state: {}'.format(state))
logging.info('instance_id: {}'.format(instance_id))
logging.info('region: {}'.format(region))

# Check to see whether a DynamoDB table already exists.  If not, create it.  This table is used to keep a record of
# instances that have been created along with their attributes.  This is necessary because when you terminate an instance
# its attributes are no longer available, so they have to be fetched from the table.

tables = dynamodb_client.list_tables()

if 'DDNS' in tables['TableNames']:
    print('DynamoDB table already exists')
else:
    try:
        create_table('DDNS')
        print('Creating DynamoDB table')
    except BaseException as e:
        logging.error('ERROR creating DynamoDB table %s' %e)
        exit()

#clean instance metadata and adding it to the table
if state == 'running':
    instance = compute.describe_instances(InstanceIds=[instance_id])
    # Remove response metadata from the response
    instance.pop('ResponseMetadata')
    # Remove null values from the response.  You cannot save a dict/JSON document in DynamoDB if it contains null values
    instance = remove_empty_from_dict(instance)
    instance_dump = json.dumps(instance,default=json_serial)
    instance_attributes = json.loads(instance_dump)
    table.put_item(
        Item={
            'InstanceId': instance_id,
            'InstanceAttributes': instance_attributes
        }
    )
else:
    # Fetch item from DynamoDB
    instance = table.get_item(
    Key={
        'InstanceId': instance_id
    },
    AttributesToGet=[
        'InstanceAttributes'
        ]
    )
    instance = instance['Item']['InstanceAttributes']

#get Name tag value as private_hostname
try:
    tags = instance['Reservations'][0]['Instances'][0]['Tags']
except:
    exit('No tags')
logging.info('tags: %s' %tags)

private_hostname = ''
for tag in tags:
    if tag['Key'] == 'Name' and tag['Value']:
        private_hostname = tag['Value'].lower()
        break
if not private_hostname:
    # Clean up DynamoDB if no Name tag found
    table.delete_item(
        Key={
            'InstanceId': instance_id
        }
    )
    exit('ERROR getting Name tag')
logging.info('private_hostname: %s' %private_hostname)

#get private ip address
private_ip = instance['Reservations'][0]['Instances'][0]['PrivateIpAddress']
logging.info('private_ip: %s' %private_ip)

#get dhcp_option_set domain name
vpc_id = instance['Reservations'][0]['Instances'][0]['VpcId']
logging.info('vpc_id: %s' %vpc_id)

vpc = ec2.Vpc(vpc_id)
logging.info('vpc: %s' %vpc)

dhcp_options_id = vpc.dhcp_options_id
logging.info('dhcp_options_id: %s' %dhcp_options_id)

dhcp_options_domain_name = get_dhcp_configurations(dhcp_options_id)
logging.info('dhcp_options_domain_name: %s' %dhcp_options_domain_name)

#create route53 private hosted zone list
hosted_zones = route53.list_hosted_zones()
private_hosted_zones_list = []
for i in hosted_zones['HostedZones']:
    if i['Config']['PrivateZone'] is True:
        private_hosted_zones_list.append(i['Name'])
logging.info('private_hosted_zones: %s' %private_hosted_zones_list)

# Set the reverse lookup zone
subnet_id = instance['Reservations'][0]['Instances'][0]['SubnetId']
subnet = ec2.Subnet(subnet_id)
cidr_block = subnet.cidr_block
subnet_mask = int(cidr_block.split('/')[-1])

reversed_ip_address = reverse_list(private_ip)
reversed_domain_prefix = reverse_list(get_reversed_domain_prefix(subnet_mask, private_ip))
reversed_lookup_zone = reversed_domain_prefix + 'in-addr.arpa.'
print('The reverse lookup zone for this instance is:', reversed_lookup_zone)

# Are DNS Hostnames and DNS Support enabled?
if is_dns_hostnames_enabled(vpc):
    print('DNS hostnames enabled for %s' % vpc_id)
else:
    print('DNS hostnames disabled for %s.  You have to enable DNS hostnames to use Route 53 private hosted zones.' % vpc_id)
if is_dns_support_enabled(vpc):
    print('DNS support enabled for %s' % vpc_id)
else:
    print('DNS support disabled for %s.  You have to enabled DNS support to use Route 53 private hosted zones.' % vpc_id)

# Check to see whether a reverse lookup zone for the instance already exists.  If it does, check to see whether
# the reverse lookup zone is associated with the instance's VPC.  If it isn't create the association.  You don't
# need to do this when you create the reverse lookup zone because the association is done automatically.
if [record for record in hosted_zones['HostedZones'] if record['Name'] == reversed_lookup_zone]:
    print('Reverse lookup zone found:', reversed_lookup_zone)
    reverse_lookup_zone_id = get_zone_id(reversed_lookup_zone)
    reverse_hosted_zone_properties = get_hosted_zone_properties(reverse_lookup_zone_id)
    if vpc_id in [x['VPCId'] for x in reverse_hosted_zone_properties['VPCs']]:
        print('Reverse lookup zone %s is associated with VPC %s' % (reverse_lookup_zone_id, vpc_id))
    else:
        print('Associating zone %s with VPC %s' % (reverse_lookup_zone_id, vpc_id))
        try:
            associate_zone(reverse_lookup_zone_id, region, vpc_id)
        except BaseException as e:
            logging.error(e)
else:
    print('No matching reverse lookup zone')
    # create private hosted zone for reverse lookups
    if state == 'running':
        try:
            create_reverse_lookup_zone(instance, reversed_lookup_zone, region)
            reverse_lookup_zone_id = get_zone_id(reversed_lookup_zone)
            print('Reverse lookup {} zone created'.format(reversed_lookup_zone))
        except BaseException as e:
            logging.error('Failed reverse lookup zone creation %s' %e)
# Wait a random amount of time.  This is a poor-mans back-off if a lot of instances are launched all at once.
#CREATE WAITER
time.sleep(random.random())

# Look to see whether there's a DHCP option set assigned to the VPC.  If there is, use the value of the domain name
# to create resource records in the appropriate Route 53 private hosted zone. This will also check to see whether
# there's an association between the instance's VPC and the private hosted zone.  If there isn't, it will create it.

if dhcp_options_domain_name in private_hosted_zones_list:
    private_hosted_zone_name = dhcp_options_domain_name
    print('Private zone found %s' % private_hosted_zone_name)
    private_hosted_zone_id = get_zone_id(private_hosted_zone_name)
    private_hosted_zone_properties = get_hosted_zone_properties(private_hosted_zone_id)
    a_record_name = private_hostname + '.' + private_hosted_zone_name
    ptr_record_name = reversed_ip_address +'in-addr.arpa'
    # create A records and PTR records
    if state == 'running':
        if vpc_id in [x['VPCId'] for x in private_hosted_zone_properties['VPCs']]:
            print('Private hosted zone %s is associated with VPC %s' % (private_hosted_zone_id, vpc_id))
        else:
            print('Associating zone %s with VPC %s' % (private_hosted_zone_id, vpc_id))
            try:
                associate_zone(private_hosted_zone_id, region,vpc_id)
            except BaseException as e:
                print('You cannot create an association with a VPC with an overlapping subdomain.\n', e)
                exit()
        try:
            print('Creating resource records', a_record_name, ptr_record_name)
            create_resource_record(private_hosted_zone_id, a_record_name, 'A', private_ip)
            create_resource_record(reverse_lookup_zone_id, ptr_record_name, 'PTR', a_record_name)
        except BaseException as e:
            print('ERROR creating resource records:', e)
    else:
        try:
            delete_resource_record(private_hosted_zone_id, a_record_name, 'A', private_ip)
            delete_resource_record(reverse_lookup_zone_id, ptr_record_name, 'PTR', a_record_name)
        except BaseException as e:
            print('ERROR deleting resource record: ', e)
else:
    print('No matching zone for %s' % dhcp_options_domain_name)

# Clean up DynamoDB after deleting records
if state != 'running':
    table.delete_item(
        Key={
            'InstanceId': instance_id
        }
    )
