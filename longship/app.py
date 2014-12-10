"""
Deployments for immutable infrastructure on AWS
"""
import argparse
import base64
import calendar
import logging
import os
import subprocess
import sys
import time

import botocore.session
import simplejson


logging.getLogger('botocore').setLevel(logging.CRITICAL)


_PROG = 'longship'
_AWS_REGION = 'us-east-1'
_APP_TABLE = 'longship_app'
_ENV_TABLE = 'longship_env'
_CONFIG_FILE = '.longship.json'


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '%s: error: %s\n' % (_PROG, message))


class Error(Exception):
    pass


def main(args):
    _setup_logging()
    app_config = _get_app_config()
    parser = _make_parser(app_config)
    opts = parser.parse_args(args)
    try:
        _run_cmd(parser, opts)
    except Error, exc:
        logging.error(str(exc))
        return 1
    return 0


def _get_app_config():
    # XXX: Search directory hierarchy for config file
    if not os.path.exists(_CONFIG_FILE):
        return {}
    with open(_CONFIG_FILE) as f:
        return simplejson.load(f)


def _setup_logging():
    fmt = '%(levelname)s: %(message)s'

    handler = logging.StreamHandler()
    formatter = logging.Formatter(fmt=fmt)
    handler.setFormatter(formatter)

    root = logging.getLogger('')
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)

    logging.addLevelName(logging.DEBUG, 'debug')
    logging.addLevelName(logging.INFO, 'info')
    logging.addLevelName(logging.WARNING, 'warning')
    logging.addLevelName(logging.ERROR, 'error')
    logging.addLevelName(logging.CRITICAL, 'critical')


def _make_parser(app_config):
    app_name = app_config.get('app_name')
    packer_root = app_config.get('packer_root')

    parser = ArgumentParser(
        prog=_PROG,
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers()

    p_app_list = subparsers.add_parser(
        'apps',
        help='show list of apps',
    )
    p_app_list.set_defaults(cmd='apps')

    p_app_info = subparsers.add_parser(
        'info',
        help='show info about an app',
    )
    p_app_info.set_defaults(cmd='info')
    p_app_info.add_argument('--app', dest='app_name', default=app_name,
                            required=app_name is None)

    p_push = subparsers.add_parser(
        'push',
        help='push a new version of an app',
    )
    p_push.set_defaults(cmd='push')
    p_push.add_argument('--app', dest='app_name', default=app_name,
                        required=app_name is None)
    p_push.add_argument('--packer-root', default=packer_root,
                        required=packer_root is None)

    p_upload = subparsers.add_parser(
        'upload',
        help='upload a new Docker image for an app',
    )
    p_upload.set_defaults(cmd='upload')
    p_upload.add_argument('--app', dest='app_name', default=app_name,
                          required=app_name is None)

    p_build = subparsers.add_parser(
        'build',
        help='build a new AMI for an app',
    )
    p_build.set_defaults(cmd='build')
    p_build.add_argument('--app', dest='app_name', default=app_name,
                         required=app_name is None)
    p_build.add_argument('--packer-root', default=packer_root,
                         required=packer_root is None)

    p_deploy = subparsers.add_parser(
        'deploy',
        help='deploy a new AMI for an app',
    )
    p_deploy.set_defaults(cmd='deploy')
    p_deploy.add_argument('--app', dest='app_name', default=app_name,
                          required=app_name is None)

    p_config = subparsers.add_parser(
        'config',
        help='show environment variables for an app',
    )
    p_config.set_defaults(cmd='config')
    p_config.add_argument('--app', dest='app_name', default=app_name,
                          required=app_name is None)

    p_set = subparsers.add_parser(
        'set',
        help='set environment variables for an app',
    )
    p_set.set_defaults(cmd='set')
    p_set.add_argument('--app', dest='app_name', default=app_name,
                       required=app_name is None)
    # XXX: Use custom action
    p_set.add_argument('config_var_map', metavar='KEY=VALUE', nargs='+',
                       help='environment variable names and values')

    p_cleanup = subparsers.add_parser(
        'cleanup',
        help='clean up old resources for an app',
    )
    p_cleanup.set_defaults(cmd='cleanup')
    p_cleanup.add_argument('--app', dest='app_name', default=app_name,
                           required=app_name is None)

    return parser


def _run_cmd(parser, opts):
    if opts.cmd == 'apps':
        _cmd_app_list()
    elif opts.cmd == 'build':
        _cmd_build(opts.app_name, opts.packer_root)
    elif opts.cmd == 'cleanup':
        _cmd_cleanup(opts.app_name)
    elif opts.cmd == 'config':
        _cmd_config_list(opts.app_name)
    elif opts.cmd == 'deploy':
        _cmd_deploy(opts.app_name)
    elif opts.cmd == 'info':
        _cmd_app_info(opts.app_name)
    elif opts.cmd == 'push':
        _cmd_push(opts.app_name, opts.packer_root)
    elif opts.cmd == 'set':
        _cmd_config_set(opts.app_name, opts.config_var_map)
    elif opts.cmd == 'upload':
        _cmd_upload(opts.app_name)


def _cmd_app_list():
    resp, data = _call(
        'dynamodb', 'Scan',
        table_name=_APP_TABLE,
        limit=20,
    )
    print '{:<20}  {:<10}  {:<15}  {:<15}  {:<15}  {:<5}'.format(
        'APP', 'ENV', 'APP_IMAGE_ID', 'AMI_IMAGE_ID', 'INSTANCE_TYPE', 'CHECK',
    )
    for i in data['Items']:
        print '{:<20}  {:<10}  {:<15}  {:<15}  {:<15}  {:<5}'.format(
            i['app_name']['S'],
            i['env_name']['S'],
            i['app_image_id']['S'] if 'app_image_id' in i else '',
            i['ami_image_id']['S'] if 'ami_image_id' in i else '',
            i['instance_type']['S'],
            i['health_check_type']['S'],
        )


def _cmd_config_list(app_name):
    resp, data = _call(
        'dynamodb', 'GetItem',
        table_name=_APP_TABLE,
        key={'app_name': {'S': app_name}},
    )
    env = simplejson.loads(data['Item']['config_vars']['S'])
    for k, v in sorted(env.items()):
        print '{}={}'.format(k, v)


def _cmd_config_set(app_name, config_var_map):
    resp, data = _call(
        'dynamodb', 'GetItem',
        table_name=_APP_TABLE,
        key={'app_name': {'S': app_name}},
    )
    env = simplejson.loads(data['Item']['config_vars']['S'])
    m = {}
    for x in config_var_map:
        if '=' not in x:
            raise Error('must include = sign: {}'.format(x))
        k, v = x.split('=', 1)
        m[k] = v
    env.update(m)
    resp, data = _call(
        'dynamodb', 'UpdateItem',
        table_name=_APP_TABLE,
        key={'app_name': {'S': app_name}},
        attribute_updates={
            'config_vars': {
                'Value': {'S': simplejson.dumps(env)},
                'Action': 'PUT',
            },
        },
    )


def _cmd_app_info(app_name):
    resp, data = _call(
        'dynamodb', 'Query',
        table_name=_APP_TABLE,
        key_conditions={
            'app_name': {
                'AttributeValueList': [{'S': app_name}],
                'ComparisonOperator': 'EQ',
            },
        },
        limit=1,
    )
    for k, v in sorted(data['Items'][0].items()):
        if k in ['config_vars', 'process_types']:
            continue
        print '{:<20} {}'.format(k + ':', v.values()[0])


def _cmd_push(app_name, packer_root):
    _cmd_upload(app_name)
    _cmd_build(app_name, packer_root)
    _cmd_deploy(app_name)


def _cmd_build(app_name, packer_root):
    timestamp = calendar.timegm(time.gmtime())
    app = _get_app(app_name)
    ami_name = '{}-{}-{}'.format(app['env_name'], app['app_name'], timestamp)
    resp, data = _call(
        'ec2', 'DescribeSecurityGroups',
        filters=[{'Name': 'group-name',
                  'Values': ['{}-{}'.format(app['env_name'], 'packer')]}],
    )
    security_group_id = data['SecurityGroups'][0]['GroupId']
    config_vars = base64.b64encode(simplejson.dumps(
        app['config_vars'],
        separators=(',', ':'),
    ))
    process_types = base64.b64encode(simplejson.dumps(
        app['process_types'],
        separators=(',', ':'),
    ))

    cmd = [
        'packer', 'build',
        '-color=false',
        '-var', 'env={}'.format(app['env_name']),
        '-var', 'iam_instance_profile={}-{}'.format(app['env_name'], 'packer'),
        '-var', 'instance_type={}'.format(app['builder_instance_type']),
        '-var', 'security_group_id={}'.format(security_group_id),
        '-var', 'subnet_id={}'.format(app['builder_subnet_id']),
        '-var', 'vpc_id={}'.format(app['vpc_id']),
        '-var', 'app_image_bucket={}'.format(app['image_bucket']),
        '-var', 'app_image_id={}'.format(app['app_image_id']),
        '-var', 'app_logplex_token={}'.format(app['logplex_token']),
        '-var', 'app_logplex_url={}'.format(app['logplex_url']),
        '-var', 'app_name={}'.format(app['app_name']),
        '-var', 'config_vars={}'.format(config_vars),
        '-var', 'process_types={}'.format(process_types),
        '-var', 'timestamp={}'.format(timestamp),
        os.path.join('packer.json'),
    ]
    logging.debug('building AMI: %s', ami_name)
    try:
        p = subprocess.Popen(cmd, cwd=packer_root)
        p.communicate()
    except KeyboardInterrupt:
        p.terminate()
        p.wait()
        raise

    if p.returncode != 0:
        raise Error('packer exited with code {}'.format(p.returncode))

    resp, data = _call(
        'ec2', 'DescribeImages',
        filters=[{'Name': 'name', 'Values': [ami_name]}],
    )
    logging.debug('updating AMI: %s', data['Images'][0]['ImageId'])
    resp, data = _call(
        'dynamodb', 'UpdateItem',
        table_name='longship_app',
        key={'app_name': {'S': app['app_name']}},
        attribute_updates={
            'ami_image_id': {
                'Value': {'S': data['Images'][0]['ImageId']},
                'Action': 'PUT',
            },
        },
    )


def _cmd_deploy(app_name):
    timestamp = calendar.timegm(time.gmtime())
    app = _get_app(app_name)
    instance_profile = _get_instance_profile(app)
    security_groups = _get_security_groups(app)

    for h in app['lifecycle_hooks']:
        h['role_arn'] = _get_role_arn(h['role_name'])
        if h['target_type'] != 'sqs':
            raise Error('lifeycle hook target type must be "sqs"')
        h['target_arn'] = _get_sqs_arn(h['target_name'])

    # XXX: get deployment lock
    asg_old = _get_old_asg(app)
    desired_capacity = asg_old['DesiredCapacity'] if asg_old is not None else 1

    _create_launch_config(app, timestamp, instance_profile, security_groups)
    _create_auto_scaling_group(app, timestamp, desired_capacity)
    _wait_for_running_instances(app, timestamp, desired_capacity)

    if asg_old:
        _shutdown_instances(asg_old)
        _delete_auto_scaling_group(asg_old)
        _delete_launch_config(asg_old['LaunchConfigurationName'])


def _cmd_upload(app_name):
    tag = '{}:{}'.format(app_name, 'build')

    cmd = ['docker', 'build', '-t', tag, '.']
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError, exc:
        raise Error(str(exc))

    cmd = ['docker', 'inspect', tag]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError, exc:
        raise Error(str(exc))
    data = simplejson.loads(output)

    app_image_id = data[0]['Id'][:12]
    app_image_tar = '{}.tpxz'.format(app_image_id)

    app = _get_app(app_name)
    if app['app_image_id'] == app_image_id:
        logging.debug('Docker image already uploaded: %s', app_image_id)
        return

    logging.debug('uploading: {} -> s3://{}/{}'.format(
        app_image_id, app['image_bucket'], app_image_tar,
    ))
    p1 = subprocess.Popen(['docker', 'save', app_image_id],
                          stdout=subprocess.PIPE)
    p2 = subprocess.Popen(['pixz'], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    p3 = subprocess.Popen(['gof3r', 'put', '-b', app['image_bucket'],
                           '-k', app_image_tar], stdin=p2.stdout)
    p2.stdout.close()
    p3.communicate()

    logging.debug('updating Docker image ID: %s', app_image_id)
    resp, data = _call(
        'dynamodb', 'UpdateItem',
        table_name=_APP_TABLE,
        key={'app_name': {'S': app_name}},
        attribute_updates={
            'app_image_id': {
                'Value': {'S': app_image_id},
                'Action': 'PUT',
            },
        },
    )


def _cmd_cleanup(app_name):
    app = _get_app(app_name)
    # XXX: clean up ASGs
    # XXX: clean up LCs
    resp, data = _call(
        'ec2', 'DescribeImages',
        filters=[
            {'Name': 'tag:env', 'Values': [app['env_name']]},
            {'Name': 'tag:app_name', 'Values': [app_name]},
        ],
    )
    for i in sorted(data['Images'], key=lambda x: x['Name']):
        # XXX: Check for active launch configuration
        if i['Name'] == 'prod-cb-app-1412702790':
            continue
        logging.debug('cleaning up AMI: %s (%s)', i['Name'], i['ImageId'])
        for m in i['BlockDeviceMappings']:
            if m['DeviceName'] != '/dev/sda1':
                continue
            if 'Ebs' not in m:
                continue
            if 'SnapshotId' not in m['Ebs']:
                continue

            resp, data = _call(
                'ec2', 'DescribeSnapshots',
                snapshot_ids=[m['Ebs']['SnapshotId']],
            )
            volume = data['Snapshots'][0]

            logging.debug('deleing volume: %s (%sG)',
                          volume['VolumeId'], volume['VolumeSize'])
            resp, data = _call('ec2', 'DeleteVolume',
                               volume_id=volume['VolumeId'])

            logging.debug('deleting snapshot: %s',
                          m['Ebs']['SnapshotId'])
            resp, data = _call('ec2', 'DeleteSnapshot',
                               snapshot_id=m['Ebs']['SnapshotId'])

        logging.debug('deregistering AMI: %s', i['ImageId'])
        resp, data = _call('ec2', 'DeregisterImage', image_id=i['ImageId'])


def _get_old_asg(app):
    elbs = _get_elbs(app)
    asgs = []
    asg_old = None
    if elbs:
        logging.debug('verifying ELB: %s', elbs[0])

        resp, data = _call('elb', 'DescribeLoadBalancers',
                           load_balancer_names=elbs)
        elb = data['LoadBalancerDescriptions'][0]

        asgs = []
        if elb['Instances']:
            resp, data = _call('autoscaling', 'DescribeAutoScalingInstances',
                               instance_ids=[i['InstanceId']
                                             for i in elb['Instances']])
            asgs = list(set(i['AutoScalingGroupName']
                            for i in data['AutoScalingInstances']))

        if len(asgs) > 1:
            logging.critical('found %d ASGs for ELB %s', len(asgs), elbs[0])

        if asgs:
            resp, data = _call('autoscaling', 'DescribeAutoScalingGroups',
                               auto_scaling_group_names=asgs)
            asg_old = data['AutoScalingGroups'][0]
        else:
            asg_old = None
    else:
        resp, data = _call('autoscaling', 'DescribeAutoScalingGroups')
        for g in data['AutoScalingGroups']:
            asg_prefix = '{}-{}-'.format(app['env_name'], app['app_name'])
            if g['AutoScalingGroupName'].startswith(asg_prefix):
                asg_old = g
    return asg_old


def _get_instance_profile(app):
    instance_profile_name = '{}-{}'.format(app['env_name'], app['app_name'])
    resp, data = _call('iam', 'GetInstanceProfile',
                       instance_profile_name=instance_profile_name)
    return data['InstanceProfile']['Arn']


def _get_security_groups(app):
    group_name = '{}-{}'.format(app['env_name'], app['app_name'])
    resp, data = _call('ec2', 'DescribeSecurityGroups', filters=[{
        'Name': 'group-name',
        'Values': [group_name],
    }])
    return [g['GroupId'] for g in data['SecurityGroups']]


def _create_launch_config(app, timestamp, instance_profile, security_groups):
    lc_name = '{}-{}-{}'.format(app['env_name'], app['app_name'], timestamp)
    logging.debug('creating LC: %s (%s)', lc_name, app['ami_image_id'])
    kwargs = {
        'launch_configuration_name': lc_name,
        'image_id': app['ami_image_id'],
        'key_name': app['key_name'],
        'security_groups': security_groups,
        'instance_type': app['instance_type'],
        'iam_instance_profile': instance_profile,
    }
    if app['user_data']:
        kwargs['user_data'] = app['user_data']
    resp, data = _call('autoscaling', 'CreateLaunchConfiguration', **kwargs)


def _get_sqs_arn(queue_name):
    resp, data = _call(
        'sqs', 'GetQueueUrl',
        queue_name=queue_name,
    )
    resp, data = _call(
        'sqs', 'GetQueueAttributes',
        queue_url=data['QueueUrl'],
        attribute_names=['QueueArn'],
    )
    return data['Attributes']['QueueArn']


def _get_role_arn(role_name):
    resp, data = _call('iam', 'GetRole', role_name=role_name)
    return data['Role']['Arn']


def _create_auto_scaling_group(app, timestamp, desired_capacity):
    asg_name = '{}-{}-{}'.format(app['env_name'], app['app_name'], timestamp)
    elbs = _get_elbs(app)
    min_size = 0
    max_size = desired_capacity
    logging.debug('creating ASG: %s (%s/%s/%s)',
                  asg_name, min_size, desired_capacity, max_size)
    kwargs = {
        'auto_scaling_group_name': asg_name,
        'launch_configuration_name': asg_name,
        'load_balancer_names': elbs,
        'health_check_type': app['health_check_type'],
        'health_check_grace_period': app.get('health_check_grace_period', 300),
        'vpc_zone_identifier': ','.join(app['app_subnet_ids']),
        'availability_zones': app['availability_zones'],
        'min_size': min_size,
        'max_size': max_size,
        'desired_capacity': desired_capacity,
        'tags': [{
            'Key': 'Name',
            'Value': '{}-{}'.format(app['env_name'], app['app_name']),
            'PropagateAtLaunch': True,
            'ResourceId': asg_name,
        }],
    }
    resp, data = _call('autoscaling', 'CreateAutoScalingGroup', **kwargs)
    for h in app['lifecycle_hooks']:
        hook_name = '{}-{}'.format(asg_name, h['hook_name'])
        logging.debug('creating ASG lifecycle hook: %s', hook_name)
        resp, data = _call(
            'autoscaling', 'PutLifecycleHook',
            auto_scaling_group_name=asg_name,
            lifecycle_hook_name=hook_name,
            lifecycle_transition=h['hook_type'],
            notification_target_arn=h['target_arn'],
            role_arn=h['role_arn'],
        )


def _wait_for_running_instances(app, timestamp, desired_capacity):
    asg_name = '{}-{}-{}'.format(app['env_name'], app['app_name'], timestamp)
    elbs = _get_elbs(app)
    while True:
        healthy = []
        resp, data = _call(
            'autoscaling', 'DescribeAutoScalingGroups',
            auto_scaling_group_names=[asg_name],
        )
        asg = data['AutoScalingGroups'][0]

        if elbs:
            resp, data = _call(
                'elb', 'DescribeInstanceHealth',
                load_balancer_name=elbs[0],
                instances=[{'InstanceId': i['InstanceId']}
                           for i in asg['Instances']],
            )

            for i in asg['Instances']:
                i['State'] = 'Invalid'
                for j in data['InstanceStates']:
                    if i['InstanceId'] == j['InstanceId']:
                        i['State'] = j['State']

            for i in asg['Instances']:
                logging.debug('asg=%s instance_id=%s lifecycle_state=%s '
                              'elb_state=%s', asg['AutoScalingGroupName'],
                              i['InstanceId'], i['LifecycleState'], i['State'])

            healthy = [i for i in asg['Instances']
                       if i['LifecycleState'] == 'InService' and
                       i['State'] == 'InService']
        else:
            for i in asg['Instances']:
                logging.debug('asg=%s instance_id=%s lifecycle_state=%s',
                              asg['AutoScalingGroupName'], i['InstanceId'],
                              i['LifecycleState'])

            healthy = [i for i in asg['Instances']
                       if i['LifecycleState'] == 'InService']

        if len(healthy) == desired_capacity:
            break
        time.sleep(5)


def _shutdown_instances(asg_old):
    resp, data = _call(
        'autoscaling', 'DescribeAutoScalingGroups',
        auto_scaling_group_names=[asg_old['AutoScalingGroupName']],
    )
    if not data['AutoScalingGroups'][0]['Instances']:
        return

    logging.debug('putting old instances into standby')
    # XXX: set min_size=0 first
    resp, data = _call(
        'autoscaling', 'EnterStandby',
        auto_scaling_group_name=asg_old['AutoScalingGroupName'],
        instance_ids=[i['InstanceId']
                      for i in data['AutoScalingGroups'][0]['Instances']],
        should_decrement_desired_capacity=True,
    )
    while True:
        resp, data = _call(
            'autoscaling', 'DescribeAutoScalingGroups',
            auto_scaling_group_names=[asg_old['AutoScalingGroupName']],
        )
        for i in data['AutoScalingGroups'][0]['Instances']:
            logging.debug('asg=%s instance_id=%s lifecycle_state=%s',
                          asg_old['AutoScalingGroupName'], i['InstanceId'],
                          i['LifecycleState'])
        if all(i['LifecycleState'] == 'Standby'
               for i in data['AutoScalingGroups'][0]['Instances']):
            break
        time.sleep(5)

    logging.debug('terminating old instances')
    resp, data = _call(
        'autoscaling', 'DescribeAutoScalingGroups',
        auto_scaling_group_names=[asg_old['AutoScalingGroupName']],
    )
    for i in data['AutoScalingGroups'][0]['Instances']:
        resp, data = _call(
            'autoscaling', 'TerminateInstanceInAutoScalingGroup',
            instance_id=i['InstanceId'],
            should_decrement_desired_capacity=False,
        )
    while True:
        resp, data = _call(
            'autoscaling', 'DescribeAutoScalingGroups',
            auto_scaling_group_names=[asg_old['AutoScalingGroupName']],
        )
        for i in data['AutoScalingGroups'][0]['Instances']:
            logging.debug('asg=%s instance_id=%s lifecycle_state=%s',
                          asg_old['AutoScalingGroupName'], i['InstanceId'],
                          i['LifecycleState'])
        if not data['AutoScalingGroups'][0]['Instances']:
            break
        time.sleep(5)


def _delete_auto_scaling_group(asg_old):
    logging.debug('deleting old ASG: %s', asg_old['AutoScalingGroupName'])
    resp, data = _call(
        'autoscaling', 'DeleteAutoScalingGroup',
        auto_scaling_group_name=asg_old['AutoScalingGroupName'],
    )
    # XXX 400 error_code == 'ScalingActivityInProgress'
    while True:
        resp, data = _call(
            'autoscaling', 'DescribeAutoScalingGroups',
            auto_scaling_group_names=[asg_old['AutoScalingGroupName']],
        )
        if not data['AutoScalingGroups']:
            break
        time.sleep(5)


def _delete_launch_config(lc_old):
    logging.debug('deleting old LC: %s', lc_old)
    resp, data = _call(
        'autoscaling', 'DeleteLaunchConfiguration',
        launch_configuration_name=lc_old,
    )
    while True:
        resp, data = _call(
            'autoscaling', 'DescribeLaunchConfigurations',
            launch_configuration_names=[lc_old],
        )
        if not data['LaunchConfigurations']:
            break
        time.sleep(5)


def _call(service, operation, **kwargs):
    session = botocore.session.get_session()
    svc = session.get_service(service)
    op = svc.get_operation(operation)
    endpoint = svc.get_endpoint(_AWS_REGION)
    #logging.debug('service=%s operation=%s', service, operation)
    return op.call(endpoint, **kwargs)


def _get_app(app_name):
    resp, data = _call(
        'dynamodb', 'GetItem',
        table_name=_APP_TABLE,
        key={'app_name': {'S': app_name}},
    )
    app_data = data['Item']

    resp, data = _call(
        'dynamodb', 'GetItem',
        table_name=_ENV_TABLE,
        key={'env_name': {'S': app_data['env_name']['S']}},
    )
    env_data = data['Item']

    app = {
        'app_name': app_data['app_name']['S'],
        'app_subnet_ids': simplejson.loads(env_data['app_subnet_ids']['S']),
        'availability_zones': simplejson.loads(
            env_data['availability_zones']['S'],
        ),
        'builder_instance_type': env_data['builder_instance_type']['S'],
        'builder_subnet_id': env_data['builder_subnet_id']['S'],
        'config_vars': simplejson.loads(app_data['config_vars']['S']),
        'env_name': env_data['env_name']['S'],
        'health_check_type': app_data['health_check_type']['S'],
        'image_bucket': env_data['image_bucket']['S'],
        'instance_type': app_data['instance_type']['S'],
        'key_name': env_data['key_name']['S'],
        'logplex_token': app_data['logplex_token']['S'],
        'logplex_url': env_data['logplex_url']['S'],
        'preferred_availability_zone': env_data[
            'preferred_availability_zone']['S'],
        'process_types': simplejson.loads(app_data['process_types']['S']),
        'vpc_id': env_data['vpc_id']['S'],
    }

    if 'ami_image_id' in app_data:
        app['ami_image_id'] = app_data['ami_image_id']['S']
    else:
        app['ami_image_id'] = ''

    if 'app_image_id' in app_data:
        app['app_image_id'] = app_data['app_image_id']['S']
    else:
        app['app_image_id'] = ''

    if 'lifecycle_hooks' in app_data:
        app['lifecycle_hooks'] = simplejson.loads(
            app_data['lifecycle_hooks']['S'],
        )
    else:
        app['lifecycle_hooks'] = []

    if 'user_data' in app_data:
        app['user_data'] = base64.b64decode(app_data['user_data']['S'])
    else:
        app['user_data'] = ''

    return app


def _get_elbs(app):
    elbs = []
    if app['health_check_type'] == 'ELB':
        elbs.append('{}-{}'.format(app['env_name'], app['app_name']))
    return elbs


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print >> sys.stderr, 'interrupted'
