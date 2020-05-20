# AutoSecureWAF
Easy to configure automation to improve security of your Web Apps by blacklisting bad actor IPs powered by GuardDuty findings.
It uses CloudFormation to create Lambdas, CloudWatch Events, DynamoDB and WAF IPsets, Amazon GuardDuty (should be already working on the account).

When GuardDuty alerts of RDPBruteForce, SSHBruteForce and PortProbeUnprotectedPort attacks it will automatically add the offending IPs (whole CIDR /24) to the IPsets.

When lauching the CloudFormation template in us-east-1 it will automatically create an IPset for CloudFormation (Global) and another IPset for ALBs (Regional). If it is launched in another region it will create the Regional IPset immediately and the Global IPset in 24 hours, this is like this because the lambda will be in charge of creating it in the required us-east-1 Region.

MANUALLY you can use the IPset created to make a Rule in a WebACL bloking those IPs. It also has a configurable duration of the block (in days) and a Max number of IPs to collect.

If it's now working on your Region create an Issue and I will fix it.

> Version 1.0

### Files:
- autoSecureLogin-template.yml, CloudFormation template to Run in your account, it is already in a public S3 bucket

- autosecurelogin.py, Lambda code that actually do the job of creating the entries in the NACL, source code only for reviewing

- autosecurelogin.zip, Zip file used by the template to deploy de Lambda, it is already in a public S3 Bucket

- autosecurelogin-cleaner.py, Lambda code that cleans up the expired entries , source code only for reviewing

- autosecurelogin-cleaner.zip, Zip file used by the template to deploy de Lambda, it is already in a public S3 Bucket

## How To Deploy
Use AWS CloudFormation to deploy the following template:

https://higher-artifacts.s3.amazonaws.com/solutions/autoSecureWAF-template.yml

### Parameters:
- *Env Tag*, use to identified the components of the template

- *Days blocked*, sets the number of days to keep the IP blocked

- *MAX number of IPs blocked*, sets the number of IPs to collect (From 1 to 1000)

`If you edit the template remember to use LF end of lines.`

`Remeber to create the WebACL Rule to BLOCK using the IPset created from the Automation`

#### Notes:

- Lambda in Python 3.8, using **WAFv2 resources

- Function uses the CIDR /24 of the offending IPs 

- To save cost the Automation DOES NOT create the WebACL nor the rule, only creates and updates the IPsets

- If the MAX IPs is reached, the older one will be replace even if is not expired

## To-Do
- A better error management
- Create the WebACL and/or the Rules to use the IPsets automatically
