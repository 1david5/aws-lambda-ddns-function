#!/bin/bash
#
#Buiding a Dynamic DNS for Route 53 using Cloudwatch Events and Lambda based on https://github.com/awslabs/aws-lambda-ddns-function
#
#https://aws.amazon.com/blogs/compute/building-a-dynamic-dns-for-route-53-using-cloudwatch-events-and-lambda/
#
#Create policy for lambda role
aws iam create-policy --policy-name ddns-lambda-policy --policy-document file://<LOCAL PATH>/ddns-pol.json

#Create lambda role
aws iam create-role --role-name ddns-lambda-role --assume-role-policy-document file://<LOCAL PATH>/ddns-trust.json

#Attach the policy to the role
aws iam attach-role-policy --role-name ddns-lambda-role --policy-arn <enter-your-policy-arn-here>

#Create a ZIP archive union.zip for union.py
zip union.zip union.py

#Create the lambda function
aws lambda create-function --function-name ddns_lambda --runtime python2.7 --role <enter-your-role-arn-here> --handler union.lambda_handler --timeout 90 --zip-file fileb://<LOCAL PATH>/union.zip

#Create the CloudWatch event that triggers the Lambda function
aws events put-rule --event-pattern "{\"source\":[\"aws.ec2\"],\"detail-type\":[\"EC2 Instance State-change Notification\"],\"detail\":{\"state\":[\"running\",\"shutting-down\",\"stopped\"]}}" --state ENABLED --name ec2_lambda_ddns_rule

#Set the target of the rule to the Lambda function
aws events put-targets --rule ec2_lambda_ddns_rule --targets Id=id123456789012,Arn=<enter-your-lambda-function-arn-here>

#Add the permissions required for the CloudWatch Events rule to execute the Lambda function
aws lambda add-permission --function-name ddns_lambda --statement-id 45 --action lambda:InvokeFunction --principal events.amazonaws.com --source-arn <enter-your-cloudwatch-events-rule-arn-here>

#Create the private hosted zone in Route 53 (follow link at the top)

#Create a DHCP options set and associate it with the VPC (follow link at the top)

