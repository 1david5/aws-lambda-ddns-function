import json
import boto3
import re
import uuid
import time
import random
from datetime import datetime

print(('Loading function NEW py3.8 with NAME_TAG!!' + datetime.now().time().isoformat()))
route53 = boto3.client('route53')
ec2 = boto3.resource('ec2')
compute = boto3.client('ec2')
dynamodb_client = boto3.client('dynamodb')
dynamodb_resource = boto3.resource('dynamodb')

def lambda_handler(event, context):
    """ Check to see whether a DynamoDB table already exists.  If not, create it.  This table is used to keep a record of
    instances that have been created along with their attributes.  This is necessary because when you terminate an instance
    its attributes are no longer available, so they have to be fetched from the table."""
    tables = dynamodb_client.list_tables()
    if 'DDNS' in tables['TableNames']:
        print('DynamoDB table already exists')
    else:
        create_table('DDNS')
        time.sleep(60)

    # Set variables
    # Get the state from the Event stream
    state = event['detail']['state']

    # Get the instance id, region, and tag collection
    instance_id = event['detail']['instance-id']
    region = event['region']
    table = dynamodb_resource.Table('DDNS')

    if state == 'running':
        instance = compute.describe_instances(InstanceIds=[instance_id])
        # Remove response metadata from the response
        instance.pop('ResponseMetadata')
        # Remove null values from the response.  You cannot save a dict/JSON document in DynamoDB if it contains null
        # values
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

    try:
        tags = instance['Reservations'][0]['Instances'][0]['Tags']
    except:
        tags = []
    # Get instance attributes
    private_ip = instance['Reservations'][0]['Instances'][0]['PrivateIpAddress']
    private_dns_name = instance['Reservations'][0]['Instances'][0]['PrivateDnsName']
    # private_host_name = private_dns_name.split('.')[0]

    private_host_name = ''
    for tag in tags:
        # print('tag', tag)
        # print('key', tag['Key'])
        if tag['Key'] == 'Name':
            private_host_name = tag['Value']
            break

    print('Our private_host_name', private_host_name)
    
    try:
        public_ip = instance['Reservations'][0]['Instances'][0]['PublicIpAddress']
        public_dns_name = instance['Reservations'][0]['Instances'][0]['PublicDnsName']
        public_host_name = public_dns_name.split('.')[0]
    except BaseException as e:
        print('Instance has no public IP or host name', e)

    # Get the subnet mask of the instance
    subnet_id = instance['Reservations'][0]['Instances'][0]['SubnetId']
    subnet = ec2.Subnet(subnet_id)
    cidr_block = subnet.cidr_block
    subnet_mask = int(cidr_block.split('/')[-1])

    reversed_ip_address = reverse_list(private_ip)
    reversed_domain_prefix = get_reversed_domain_prefix(subnet_mask, private_ip)
    reversed_domain_prefix = reverse_list(reversed_domain_prefix)

    # Set the reverse lookup zone
    reversed_lookup_zone = reversed_domain_prefix + 'in-addr.arpa.'
    print('The reverse lookup zone for this instance is:', reversed_lookup_zone)

    # Get VPC id
    vpc_id = instance['Reservations'][0]['Instances'][0]['VpcId']
    vpc = ec2.Vpc(vpc_id)

    # Are DNS Hostnames and DNS Support enabled?
    if is_dns_hostnames_enabled(vpc):
        print('DNS hostnames enabled for %s' % vpc_id)
    else:
        print('DNS hostnames disabled for %s.  You have to enable DNS hostnames to use Route 53 private hosted zones.' % vpc_id)
    if is_dns_support_enabled(vpc):
        print('DNS support enabled for %s' % vpc_id)
    else:
        print('DNS support disabled for %s.  You have to enabled DNS support to use Route 53 private hosted zones.' % vpc_id)

    # Create the public and private hosted zone collections.  These are collections of zones in Route 53.
    hosted_zones = route53.list_hosted_zones()
    private_hosted_zones = [x for x in hosted_zones['HostedZones'] if x['Config']['PrivateZone'] is True]
    private_hosted_zone_collection = [x['Name'] for x in private_hosted_zones]
    public_hosted_zones = [x for x in hosted_zones['HostedZones'] if x['Config']['PrivateZone'] is False]
    public_hosted_zones_collection = [x['Name'] for x in public_hosted_zones]
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
                print(e)
    else:
        print('No matching reverse lookup zone')
        # create private hosted zone for reverse lookups
        if state == 'running':
            create_reverse_lookup_zone(instance, reversed_domain_prefix, region)
            reverse_lookup_zone_id = get_zone_id(reversed_lookup_zone)
    # Wait a random amount of time.  This is a poor-mans back-off if a lot of instances are launched all at once.
    time.sleep(random.random())

    # Loop through the instance's tags, looking for the zone and cname tags.  If either of these tags exist, check
    # to make sure that the name is valid.  If it is and if there's a matching zone in DNS, create A and PTR records.
    for tag in tags:
        if 'ZONE' in tag.get('Key',{}).lstrip().upper():
            if is_valid_hostname(tag.get('Value')):
                if tag.get('Value').lstrip().lower() in private_hosted_zone_collection:
                    print('Private zone found:', tag.get('Value'))
                    private_hosted_zone_name = tag.get('Value').lstrip().lower()
                    private_hosted_zone_id = get_zone_id(private_hosted_zone_name)
                    private_hosted_zone_properties = get_hosted_zone_properties(private_hosted_zone_id)
                    if state == 'running':
                        if vpc_id in [x['VPCId'] for x in private_hosted_zone_properties['VPCs']]:
                            print('Private hosted zone %s is associated with VPC %s' % (private_hosted_zone_id, vpc_id))
                        else:
                            print('Associating zone %s with VPC %s' % (private_hosted_zone_id, vpc_id))
                            try:
                                associate_zone(private_hosted_zone_id, region, vpc_id)
                            except BaseException as e:
                                print('You cannot create an association with a VPC with an overlapping subdomain.\n', e)
                                exit()
                        try:
                            create_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                            create_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
                        except BaseException as e:
                            print(e)
                    else:
                        try:
                            delete_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                            delete_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
                        except BaseException as e:
                            print(e)
                    # create PTR record
                elif tag.get('Value').lstrip().lower() in public_hosted_zones_collection:
                    print('Public zone found', tag.get('Value'))
                    public_hosted_zone_name = tag.get('Value').lstrip().lower()
                    public_hosted_zone_id = get_zone_id(public_hosted_zone_name)
                    # create A record in public zone
                    if state =='running':
                        try:
                            create_resource_record(public_hosted_zone_id, public_host_name, public_hosted_zone_name, 'A', public_ip)
                        except BaseException as e:
                            print(e)
                    else:
                        try:
                            delete_resource_record(public_hosted_zone_id, public_host_name, public_hosted_zone_name, 'A', public_ip)
                        except BaseException as e:
                            print(e)
                else:
                    print('No matching zone found for %s' % tag.get('Value'))
            else:
                print('%s is not a valid host name' % tag.get('Value'))
        # Consider making this an elif CNAME
        else:
            print('The tag \'%s\' is not a zone tag' % tag.get('Key'))
        if 'CNAME' in tag.get('Key',{}).lstrip().upper():
            if is_valid_hostname(tag.get('Value')):
                cname = tag.get('Value').lstrip().lower()
                cname_host_name = cname.split('.')[0]
                cname_domain_suffix = cname[cname.find('.')+1:]
                cname_domain_suffix_id = get_zone_id(cname_domain_suffix)
                for cname_private_hosted_zone in private_hosted_zone_collection:
                    cname_private_hosted_zone_id = get_zone_id(cname_private_hosted_zone)
                    if cname_domain_suffix_id == cname_private_hosted_zone_id:
                        if cname.endswith(cname_private_hosted_zone):
                            #create CNAME record in private zone
                            if state == 'running':
                                try:
                                    create_resource_record(cname_private_hosted_zone_id, cname_host_name, cname_private_hosted_zone, 'CNAME', private_dns_name)
                                except BaseException as e:
                                    print(e)
                            else:
                                try:
                                    delete_resource_record(cname_private_hosted_zone_id, cname_host_name, cname_private_hosted_zone, 'CNAME', private_dns_name)
                                except BaseException as e:
                                    print(e)
                for cname_public_hosted_zone in public_hosted_zones_collection:
                    if cname.endswith(cname_public_hosted_zone):
                        cname_public_hosted_zone_id = get_zone_id(cname_public_hosted_zone)
                        #create CNAME record in public zone
                        if state == 'running':
                            try:
                                create_resource_record(cname_public_hosted_zone_id, cname_host_name, cname_public_hosted_zone, 'CNAME', public_dns_name)
                            except BaseException as e:
                                print(e)
                        else:
                            try:
                                delete_resource_record(cname_public_hosted_zone_id, cname_host_name, cname_public_hosted_zone, 'CNAME', public_dns_name)
                            except BaseException as e:
                                print(e)
    # Is there a DHCP option set?
    # Get DHCP option set configuration
    try:
        dhcp_options_id = vpc.dhcp_options_id
        dhcp_configurations = get_dhcp_configurations(dhcp_options_id)
    except BaseException as e:
        print('No DHCP option set assigned to this VPC\n', e)
        exit()
    # Look to see whether there's a DHCP option set assigned to the VPC.  If there is, use the value of the domain name
    # to create resource records in the appropriate Route 53 private hosted zone. This will also check to see whether
    # there's an association between the instance's VPC and the private hosted zone.  If there isn't, it will create it.
    for configuration in dhcp_configurations:
        if configuration[0] in private_hosted_zone_collection:
            private_hosted_zone_name = configuration[0]
            print('Private zone found %s' % private_hosted_zone_name)
            # TODO need a way to prevent overlapping subdomains
            private_hosted_zone_id = get_zone_id(private_hosted_zone_name)
            private_hosted_zone_properties = get_hosted_zone_properties(private_hosted_zone_id)
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
                    create_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                    create_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
                except BaseException as e:
                    print('Line 267: ', e)
            else:
                try:
                    delete_resource_record(private_hosted_zone_id, private_host_name, private_hosted_zone_name, 'A', private_ip)
                    delete_resource_record(reverse_lookup_zone_id, reversed_ip_address, 'in-addr.arpa', 'PTR', private_dns_name)
                except BaseException as e:
                    print('Line 273: ', e)
        else:
            print('No matching zone for %s' % configuration[0])
            
    # Clean up DynamoDB after deleting records
    if state != 'running':
        table.delete_item(
            Key={
                'InstanceId': instance_id
            }
        )
        
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

def create_resource_record(zone_id, host_name, hosted_zone_name, type, value):
    """This function creates resource records in the hosted zone passed by the calling function."""
    print('Updating %s record %s in zone %s ' % (type, host_name, hosted_zone_name))
    if host_name[-1] != '.':
        host_name = host_name + '.'
    route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": host_name + hosted_zone_name,
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

def delete_resource_record(zone_id, host_name, hosted_zone_name, type, value):
    """This function deletes resource records from the hosted zone passed by the calling function."""
    print('Deleting %s record %s in zone %s' % (type, host_name, hosted_zone_name))
    if host_name[-1] != '.':
        host_name = host_name + '.'
    route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": host_name + hosted_zone_name,
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

def is_valid_hostname(hostname):
    """This function checks to see whether the hostname entered into the zone and cname tags is a valid hostname."""
    if hostname is None or len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def get_dhcp_configurations(dhcp_options_id):
    """This function returns the names of the zones/domains that are in the option set."""
    zone_names = []
    dhcp_options = ec2.DhcpOptions(dhcp_options_id)
    dhcp_configurations = dhcp_options.dhcp_configurations
    for configuration in dhcp_configurations:
        zone_names.append([x['Value'] + '.' for x in configuration['Values']])
    return zone_names

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

def create_reverse_lookup_zone(instance, reversed_domain_prefix, region):
    """Creates the reverse lookup zone."""
    print('Creating reverse lookup zone %s' % reversed_domain_prefix + 'in.addr.arpa.')
    route53.create_hosted_zone(
        Name = reversed_domain_prefix + 'in-addr.arpa.',
        VPC = {
            'VPCRegion':region,
            'VPCId': instance['Reservations'][0]['Instances'][0]['VpcId']
        },
        CallerReference=str(uuid.uuid1()),
        HostedZoneConfig={
            'Comment': 'Updated by Lambda DDNS',
        },
    )

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")

def remove_empty_from_dict(d):
    """Removes empty keys from dictionary"""
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d

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

def get_hosted_zone_properties(zone_id):
    hosted_zone_properties = route53.get_hosted_zone(Id=zone_id)
    hosted_zone_properties.pop('ResponseMetadata')
    return hosted_zone_properties