from __future__ import print_function
import json
import boto3
import logging
from time import sleep
from botocore.client import ClientError

d_inv = {}
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Entrypoint. Handle CloudWatch SNS JSON event

    :param event:dict
    :param context:dict
    """
    message = json.loads(event['Records'][0]['Sns']['Message'])
    name = str(message['AlarmName']).split("-", 1)
    shortname = name[0]
    instance = message['Trigger']['Dimensions'][0]['value']
    eip = str(get_ec2_eip(instance))
    standby = get_ec2_id(shortname)
    logging.info("CloudWatch Alarm Event {0}-{1} received for instance {2} ({3})"
                 .format(name[0], name[1], instance, shortname))
    logging.info("Master InstanceId: " + instance)
    logging.info("Standby Instance: " + standby)
    logging.info("Elastic IP: " + eip)
    logging.info("Reassociating EIP {0} from instance {1} to standby instance {2}..." .format(eip, instance, standby))
    try:
        eip_switch(eip, standby)
    except ClientError, e:
        logging.error("EIP Association ClientError: {0}" .format(e))
        sns_publish("arn:aws:sns:eu-west-1:xxxxxxxxxxxx:mail", "ERROR: EIP Reassociation for {0}",
                    'The CloudWatch Alarm {1}-{2} triggered a Lambda function that attempted to reassociate the {3} '
                    'EIP {4} from {5} to {6} but there was an error. ClientError: {7}'
                    .format(name[0], name[0], name[1], shortname, eip, instance, standby, e))
    sleep(3)
    standby_eip = get_ec2_eip(standby)
    logging.info("Reassociation complete. Standby instance EIP is now " + standby_eip)
    sns_publish("arn:aws:sns:eu-west-1:xxxxxxxxxxxx:mail", "EIP Reassociation for {0}",
                "The CloudWatch Alarm {1}-{2} triggered a Lambda function that has reassociated the {3} "
                "EIP {4} from {5} to {6}"
                .format(name[0], name[0], name[1], shortname, eip, instance, standby))


def extract(dict_in, dict_out):
    """Extract nested dictionary key/values into flat dict
    Example: extract(in, out)
    :param dict_in:dict
    :param dict_out:dict
    """
    for key, value in dict_in.iteritems():
        if isinstance(value, dict):
            extract(value, dict_out)
        elif isinstance(value, list):
            for i in value:
                extract(i, dict_out)
        else:
            dict_out[key] = value


def sns_publish(arn, subject, msg):
    """Publish SNS event
    Example: sns_publish('arn:aws:sns:eu-west-1:xxxxxxxxxxxx:mail','My Subject','My Message')
    :param arn:
    :param subject:
    :param msg:
    """
    sns = boto3.client('sns', region_name='eu-west-1')
    sns.publish(
        TopicArn=arn,
        Message=msg,
        Subject=subject
    )


def eip_switch(eip, standby):
    """Reassociate EIP to new InstanceID
    Example: eip_switch('52.x.x.x', 'i-xxxxxxx')
    :param eip: str
    :param standby: str
    :return: dict
    """
    ec2 = boto3.client('ec2', region_name='eu-west-1')
    response = ec2.associate_address(
        DryRun=False,
        InstanceId=standby,
        PublicIp=eip,
        AllowReassociation=True
        )
    return response


def get_ec2_eip(instance):
    """Get the EIP from an InstanceId
    Example: get_ec2_eip('i-xxxxxx')
    Returns: Elastic IP address associated with given InstanceId
    :param instance: str
    :return: str
    """
    ec2 = boto3.client('ec2', region_name='eu-west-1')
    d = {
        'Name': 'instance-id',
        'Values': [instance]
    }
    r = ec2.describe_instances(
        Filters=[d]
        )
    global d_inv
    extract(r, d_inv)
    return d_inv['PublicIpAddress']


def get_ec2_id(tag):
    """Get ec2 InstanceId from tagName value (wildcard)
    Example: get_ec2_id
    :rtype: dict
    """
    ec2 = boto3.client('ec2', region_name='eu-west-1')
    d = {
        'Name': 'tag:Name',
        'Values': [tag + '*standby']
    }
    r = ec2.describe_instances(
        Filters=[d]
    )
    global d_inv
    extract(r, d_inv)
    return d_inv['InstanceId']