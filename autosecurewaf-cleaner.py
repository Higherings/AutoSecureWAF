# igarcia 2020-05
# Version 1.0.0
# Automation to Secure WAFv2 (Web Application Firewall)
# Cleaner function to remove expired IPs in IPsets and updates DynamoDB table
# Python 3.8 - AWS WAFv2

import json
import boto3
import os
import datetime
from boto3.dynamodb.conditions import Key

session = boto3.session.Session()
dynamodb = session.resource('dynamodb')
table = dynamodb.Table(os.environ['DDBTABLE'])
wafv2_client = session.client('wafv2')
wafv2_global_client = session.client('wafv2', region_name='us-east-1')

DAYS_BLOCK = int(os.environ['BLOCKDAYS'])
REGION = os.environ['REGION']
ENV = os.environ['ENVIRONMENT']
IPSETID_G = os.environ['IPSETIDG']
IPSETID_R = os.environ['IPSETIDR']

# Creates the Global (CloudFront) IPset in us-east-1 if does not exist
def createGlobalIPset():

    global DAYS_BLOCK
    global REGION
    global ENV
    global IPSETID_G
    global IPSETID_R

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

    global DAYS_BLOCK
    global REGION
    global ENV
    global IPSETID_G
    global IPSETID_R

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

    global DAYS_BLOCK
    global REGION
    global ENV
    global IPSETID_G
    global IPSETID_R

    # Finds date to clean
    curr_date = datetime.datetime.now()
    delta = datetime.timedelta(days=DAYS_BLOCK)
    clean_date = (curr_date - delta).strftime("%Y-%m-%d")

    # Gets to see if is first run, if it is, makes the setup complete
    setup_complete = table.get_item(Key={"pk":"setup"}) 
    if not setup_complete.get('Item'):
        if IPSETID_G == REGION:
            IPSETID_G = createGlobalIPset() # All response
        response = table.put_item(Item={"pk":"numberips","rule":0,"lastdate":curr_date.strftime("%Y-%m-%d")})
        response = table.put_item(Item={"pk":"setup","rule":1,"lastdate":curr_date.strftime("%Y-%m-%d"),"IPset_regional":IPSETID_R,"IPset_global":IPSETID_G})

    ips_clean = 0
    
    # Gets Rules by date to clean
    cidrs = table.scan(
        ProjectionExpression="pk",
        Select="SPECIFIC_ATTRIBUTES",
        FilterExpression=Key("date").lt(clean_date)
    )
    with table.batch_writer() as batch:
        for cidr in cidrs['Items']:
            response = batch.delete_item(Key={"pk":cidr['pk']})
            ips_clean+=1
    
    while 'LastEvaluatedKey' in cidrs: # Gets more IPs by date to clean
        cidrs = table.scan(
            ProjectionExpression="pk",
            Select="SPECIFIC_ATTRIBUTES",
            FilterExpression=Key("date").lt(clean_date),
            ExclusiveStartKey=cidrs['LastEvaluatedKey']
        )
        with table.batch_writer() as batch:
            for cidr in cidrs['Items']:
                response = batch.delete_item(Key={"pk":cidr['pk']})
                ips_clean+=1
    
    # If is neccesary to update IPsets
    if ips_clean > 0:
        updateIPsets()
    print("INFO: IPsets updated: {} IPs removed".format(ips_clean))

    # Gets available Rule numbers
    number_ips = table.get_item(Key={"pk":"numberips"})
    
    # True if there are no rules yet
    if not number_ips.get('Item'):
        ips = 0
    else:
        ips = int(number_ips['Item']['rule'])-ips_clean
        response = table.put_item(Item={"pk":"numberips","rule":ips,"lastdate":curr_date.strftime("%Y-%m-%d")})
    
    return None
