# igarcia 2020-05
# Version 1.0.0
# Automation to Secure WAFv2 (Web Application Firewall)
# Gets updates from GuardDuty (must be already configured) and blocks the CIDR /24 of attackers
# Main function to create entries in the WAF IPset used by the specified Web ACL and updates de DynamoDB table
# Python 3.8 - AWS WAFv2

import json
import boto3
import os
from boto3.dynamodb.conditions import Key

session = boto3.session.Session()
dynamodb = session.resource('dynamodb')
table = dynamodb.Table(os.environ['DDBTABLE']) #'AutoSecureWAFTable-Test2'
wafv2_client = session.client('wafv2')
wafv2_global_client = session.client('wafv2', region_name='us-east-1')

REGION = os.environ['REGION']
ENV = os.environ['ENVIRONMENT']
IPSETID_G = os.environ['IPSETIDG']
IPSETID_R = os.environ['IPSETIDR']
MAXIPS = int(os.environ['MAXIPS'])

# Creates the Global (CloudFront) IPset in us-east-1 if does not exist
def createGlobalIPset():

    global REGION
    global ENV
    global IPSETID_G
    global IPSETID_R
    global MAXIPS

    try:
        wafv2_global = wafv2_global_client.create_ip_set(
            Name='-'.join(["AutoSecureWAF-IPset-Block-Global",ENV]),
            Scope='CLOUDFRONT',
            Description='-'.join(["AutoSecureWAF-IPset-Block-Global",ENV]),
            IPAddressVersion='IPV4',
            Addresses=['127.0.0.1/32']
        )
        wafv2_global = '|'.join([wafv2_global['Summary']['Name'],wafv2_global['Summary']['Id'],'CLOUDFRONT'])
    except Exception as e:
        print("ERROR: Unable to create IPset in us-east-1 for CloudFront")
        print(e)
        wafv2_global = REGION
    return wafv2_global

# Updates de IPsets
def updateIPsets():

    global REGION
    global ENV
    global IPSETID_G
    global IPSETID_R
    global MAXIPS

    cidrs = []
    setup = table.get_item(Key={"pk":"setup"})
    ipset_name_g = setup['Item']['IPset_global'].split('|')[0]
    ipset_id_g = setup['Item']['IPset_global'].split('|')[1]
    ipset_name_r = setup['Item']['IPset_regional'].split('|')[0]
    ipset_id_r = setup['Item']['IPset_regional'].split('|')[1]

    cidrs_db = table.scan(
        ProjectionExpression="pk",
        Select="SPECIFIC_ATTRIBUTES",
        FilterExpression=Key("pk").begins_with("cidr#")
    )
    for cidr in cidrs_db['Items']:
        cidrs.append(cidr['pk'].split('#')[1])

    while 'LastEvaluatedKey' in cidrs_db:
        cidrs_db = table.scan(
            ProjectionExpression="pk",
            Select="SPECIFIC_ATTRIBUTES",
            FilterExpression=Key("pk").begins_with("cidr#"),
            ExclusiveStartKey=cidrs_db['LastEvaluatedKey']
        )
        for cidr in cidrs_db['Items']:
            cidrs.append(cidr['pk'].split('#')[1])

    try:
        if ipset_name_g != REGION:
            ipset_global = wafv2_global_client.get_ip_set(
                Name = ipset_name_g,
                Id = ipset_id_g,
                Scope = 'CLOUDFRONT'
            )

            response = wafv2_global_client.update_ip_set(
                Name = ipset_name_g,
                Scope = 'CLOUDFRONT',
                Id = ipset_id_g,
                LockToken = ipset_global['LockToken'],
                Addresses = cidrs
            )
        else:
            print("WARNING: There is no IPset for CloudFront")

        ipset_regional = wafv2_client.get_ip_set(
            Name = ipset_name_r,
            Id = ipset_id_r,
            Scope = 'REGIONAL'
        )

        response = wafv2_client.update_ip_set(
            Name = ipset_name_r,
            Scope = 'REGIONAL',
            Id = ipset_id_r,
            LockToken = ipset_regional['LockToken'],
            Addresses = cidrs
        )
    except Exception as e:
        print("ERROR: Unable to update IPsets")
        print(response)
        print(e)


    return None

def lambda_handler(event, context):
    
    global REGION
    global ENV
    global IPSETID_G
    global IPSETID_R
    global MAXIPS

    # Gets DATA from event
    e_type = event['detail']['service']['action']['actionType']
    if e_type == 'PORT_PROBE':
        e_ip = event['detail']['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails']['ipAddressV4']
        e_country = event['detail']['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails']['country']['countryName']
    else: # 'NETWORK_CONNECTION'
        e_ip = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']
        e_country = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['country']['countryName']

    e_date = event['detail']['service']['eventLastSeen']
    cidr = '.'.join(e_ip.split('.')[0:3])+'.0/24'
    cidr_del = ""
    to_remove = False

    # Gets to see if is first run, if it is, makes the setup complete
    setup_complete = table.get_item(Key={"pk":"setup"}) 
    if not setup_complete.get('Item'):
        if IPSETID_G == REGION:
            IPSETID_G = createGlobalIPset() # All response
        response = table.put_item(Item={"pk":"numberips","rule":0,"lastdate":e_date})
        response = table.put_item(Item={"pk":"setup","rule":1,"lastdate":e_date,"IPset_regional":IPSETID_R,"IPset_global":IPSETID_G})

    # Gets Number of IPs
    numberips = table.get_item(Key={"pk":"numberips"})
    numberips_n = int(numberips['Item']['rule'])
    numberips_n+=1

    # Checks the limit of Rules to Create
    if numberips_n >= MAXIPS:
        numberips_n = MAXIPS

        # Will replace the oldest rule
        dates = []
        rules = table.scan(
            ProjectionExpression="pk, #rule, #date",
            Select="SPECIFIC_ATTRIBUTES",
            FilterExpression=Key("pk").begins_with("cidr#"),
            ExpressionAttributeNames={"#rule": "rule","#date": "date"}
        )
        for rule in rules['Items']:
            dates.append(rule['date'])

        while 'LastEvaluatedKey' in rules:
                rules = table.scan(
                    ProjectionExpression="pk, #rule, #date",
                    Select="SPECIFIC_ATTRIBUTES",
                    FilterExpression=Key("pk").begins_with("cidr#"),
                    ExpressionAttributeNames={"#rule": "rule","#date": "date"},
                    ExclusiveStartKey=rules['LastEvaluatedKey']
                )
                for rule in rules['Items']:
                    dates.append(rule['date'])

        dates.sort()    # Dates sorted from oldest to newest
        rule = None

        for rule in rules['Items']:
            if rule['date'] == dates[0]:  # Found oldest rule
                cidr_del = rule['pk']
                to_remove = True
                break
        print("INFO: MAX IPs reached. Oldest IP replaced.")
    
    # Updates Rules in DynamoDB
    try:
        response = table.put_item(
            Item = {
                "pk":"cidr#"+cidr,
                "country":e_country,
                "rule":numberips_n,
                "date":e_date,
                "type":e_type
            },
            ConditionExpression = "attribute_not_exists(pk)"
        )
        if to_remove:
            response = table.delete_item(Key={"pk":cidr_del})
    except Exception as e:
        # If Rule already Exist, Updates new date
        if e.response['Error']['Code'] == "ConditionalCheckFailedException":
            rule_db = table.get_item(Key={"pk":"cidr#"+cidr})
            response = table.put_item(
                Item = {
                    "pk":rule_db['Item']['pk'],
                    "country":rule_db['Item']['country'],
                    "rule":int(rule_db['Item']['rule']),
                    "date":e_date,
                    "type":rule_db['Item']['type']
                }
            )
            print("INFO: IPsets updated: BLOCK CIDR {}".format(cidr))
    else:
        # Updates Next Rule number in DynamoDB
        response = table.put_item(Item={"pk":"numberips","rule":numberips_n,"lastdate":e_date})
        
        # Modifies IPsets
        updateIPsets()
        print("INFO: IPsets updated: BLOCK CIDR {}".format(cidr))
    
        return None
