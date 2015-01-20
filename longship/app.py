"""
Deployments for immutable infrastructure on AWS
"""
import argparse
import base64
import calendar
import logging
import os
import requests
import requests.exceptions
import requests.packages.urllib3.exceptions
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urlparse

import botocore.session
import simplejson


logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)


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
    image_tag = app_config.get('image_tag')

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
    p_push.add_argument('--image-tag', default=image_tag,
                        required=image_tag is None)

    p_upload = subparsers.add_parser(
        'upload',
        help='upload a new Docker image for an app',
    )
    p_upload.set_defaults(cmd='upload')
    p_upload.add_argument('--app', dest='app_name', default=app_name,
                          required=app_name is None)
    p_upload.add_argument('--image-tag', default=image_tag,
                         required=image_tag is None)

    p_build = subparsers.add_parser(
        'build',
        help='build a new AMI for an app',
    )
    p_build.set_defaults(cmd='build')
    p_build.add_argument('--app', dest='app_name', default=app_name,
                         required=app_name is None)

    p_deploy = subparsers.add_parser(
        'deploy',
        help='deploy a new AMI for an app',
    )
    p_deploy.set_defaults(cmd='deploy')
    p_deploy.add_argument('--app', dest='app_name', default=app_name,
                          required=app_name is None)

    p_log = subparsers.add_parser(
        'log',
        help='display log for an app',
    )
    p_log.set_defaults(cmd='log')
    p_log.add_argument('--app', dest='app_name', default=app_name,
                       required=app_name is None)
    p_log.add_argument('-n', '--num', dest='num')
    p_log.add_argument('-t', '--tail', dest='tail', action='store_true')

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
        _cmd_build(opts.app_name)
    elif opts.cmd == 'cleanup':
        _cmd_cleanup(opts.app_name)
    elif opts.cmd == 'config':
        _cmd_config_list(opts.app_name)
    elif opts.cmd == 'deploy':
        _cmd_deploy(opts.app_name)
    elif opts.cmd == 'log':
        _cmd_log(opts.app_name, opts.num, opts.tail)
    elif opts.cmd == 'info':
        _cmd_app_info(opts.app_name)
    elif opts.cmd == 'push':
        _cmd_push(opts.app_name, opts.image_tag)
    elif opts.cmd == 'set':
        _cmd_config_set(opts.app_name, opts.config_var_map)
    elif opts.cmd == 'upload':
        _cmd_upload(opts.app_name, opts.image_tag)


def _cmd_app_list():
    resp, data = _call(
        'dynamodb', 'Scan',
        table_name=_APP_TABLE,
        limit=20,
    )
    print '{:<20}  {:<10}  {:<15}  {:<15}  {:<15}'.format(
        'APP', 'ENV', 'APP_IMAGE_ID', 'IMAGE_ID', 'INSTANCE_TYPE',
    )
    for i in data['Items']:
        print '{:<20}  {:<10}  {:<15}  {:<15}  {:<15}'.format(
            i['app_name']['S'],
            i['env_name']['S'],
            i['app_image_id']['S'] if 'app_image_id' in i else '',
            i['image_id']['S'] if 'image_id' in i else '',
            i['instance_type']['S'],
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
                'Value': {'S': simplejson.dumps(env, sort_keys=True,
                                                separators=(',', ':'))},
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
        print '{:<20} {}'.format(k + ':', v.values()[0])


def _cmd_push(app_name, image_tag):
    _cmd_upload(app_name, image_tag)
    _cmd_build(app_name)
    _cmd_deploy(app_name)


def _cmd_build(app_name):
    timestamp = calendar.timegm(time.gmtime())
    app = _get_app(app_name)
    ami_name = '{}-{}-{}'.format(app['env_name'], app['app_name'], timestamp)
    resp, data = _call(
        'ec2', 'DescribeSecurityGroups',
        filters=[{'Name': 'group-name',
                  'Values': ['{}-{}'.format(app['env_name'], 'packer')]}],
    )
    security_group_id = data['SecurityGroups'][0]['GroupId']
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
        '-var', 'app_logplex_token={}'.format(app['logplex_token']),
        '-var', 'app_logplex_input_url={}'.format(app['logplex_input_url']),
        '-var', 'app_name={}'.format(app['app_name']),
        '-var', 'timestamp={}'.format(timestamp),
        'packer.json',
    ]

    logging.debug('building AMI: %s', ami_name)
    packer_root = None
    try:
        packer_root = tempfile.mkdtemp()
        td_fname = os.path.join(packer_root, 'task-definition.json')
        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        for f in ('create-task', 'packer.json', 'provision'):
            src = os.path.join(data_dir, f)
            dst = os.path.join(packer_root, f)
            logging.debug('copying: %s -> %s', src, dst)
            shutil.copyfile(src, dst)
        if app.get('task_definition'):
            with open(td_fname, 'w') as f:
                f.write(simplejson.dumps(app['task_definition'],
                                         sort_keys=True, indent=2))
        p = subprocess.Popen(cmd, cwd=packer_root)
        p.communicate()
    except KeyboardInterrupt:
        p.terminate()
        p.wait()
        raise
    finally:
        if packer_root is not None and os.path.exists(packer_root):
            logging.debug('deleting: %s', packer_root)
            shutil.rmtree(packer_root)

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
            'image_id': {
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


def _cmd_log(app_name, num, tail):
    app = _get_app(app_name)
    if not app['logplex_channel_id']:
        logging.error('logplex_channel_id not found')

    url = urlparse.urljoin(app['logplex_url'], '/v2/sessions')
    payload = {'channel_id': app['logplex_channel_id']}
    if num:
        payload['num'] = num
    if tail:
        payload['tail'] = True

    s = requests.Session()
    try:
        r = s.post(url, auth=(app['logplex_user'], app['logplex_password']),
                   data=simplejson.dumps(payload))
    except requests.exceptions.ConnectionError as exc:
        if isinstance(exc.args[0], requests.packages.urllib3.exceptions.ProtocolError) and isinstance(exc.args[0].args[1], socket.error):
            raise Error('{}: {}'.format(exc.args[0].args[1].args[1], url))
        else:
            raise Error(str(exc))
    data = r.json()
    url = urlparse.urljoin(app['logplex_url'], data['url'])
    while True:
        r = s.get(url, stream=True, params={'srv': '1'})
        if r.status_code != 200:
            logging.error('session does not exist: %s', data['url'])
            break

        while True:
            # raw = urllib3 HTTPResponse
            # raw._fp = httplib HTTPResponse
            # raw._fp.fp = socket file-like object returned by socket.makefile()
            # raw._fp.fp._sock is the actual socket where we could call recv()
            line = r.raw._fp.fp.readline(8192)
            if not line:
                break
            print line,

        if not tail:
            break


def _cmd_upload(app_name, image_tag):
    app = _get_app(app_name)

    cmd = ['docker', 'build', '-t', image_tag, '.']
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError, exc:
        raise Error(str(exc))

    cmd = ['docker', 'inspect', image_tag]
    try:
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError, exc:
        raise Error(str(exc))
    data = simplejson.loads(output)

    app_image_id = data[0]['Id'][:12]
    app_image_tar = '{}.tpxz'.format(app_image_id)

    resp, data = _call(
        's3', 'GetObject',
        bucket=app['image_bucket'],
        key=app_image_tar,
    )
    if resp.status_code == 200:
        logging.debug('Docker image already uploaded: %s', app_image_id)
    else:
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

    for i, c in enumerate(app['task_definition']):
        if c['image_tag'] != image_tag:
            continue
        logging.debug('updating Docker image ID: %s -> %s', c['name'],
                      app_image_id)
        update_expression = 'set task_definition[{}].image = :image'.format(i)
        resp, data = _call(
            'dynamodb', 'UpdateItem',
            table_name=_APP_TABLE,
            key={'app_name': {'S': app_name}},
            update_expression=update_expression,
            expression_attribute_values={':image': {'S': app_image_id}},
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
    asgs = []
    asg_old = None
    if app['elb_names']:
        logging.debug('verifying ELB: %s', app['elb_names'][0])

        resp, data = _call('elb', 'DescribeLoadBalancers',
                           load_balancer_names=app['elb_names'])
        elb = data['LoadBalancerDescriptions'][0]

        asgs = []
        if elb['Instances']:
            resp, data = _call('autoscaling', 'DescribeAutoScalingInstances',
                               instance_ids=[i['InstanceId']
                                             for i in elb['Instances']])
            asgs = list(set(i['AutoScalingGroupName']
                            for i in data['AutoScalingInstances']))

        if len(asgs) > 1:
            logging.critical('found %d ASGs for ELB %s', len(asgs),
                             app['elb_names'][0])

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
    if not app['instance_profile_name']:
        return None
    resp, data = _call('iam', 'GetInstanceProfile',
                       instance_profile_name=app['instance_profile_name'])
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
    logging.debug('creating LC: %s (%s)', lc_name, app['image_id'])
    kwargs = {
        'launch_configuration_name': lc_name,
        'image_id': app['image_id'],
        'key_name': app['key_name'],
        'security_groups': security_groups,
        'instance_type': app['instance_type'],
    }
    if app['instance_profile_name']:
        logging.debug('iam_instance_profile=%s', instance_profile)
        kwargs['iam_instance_profile'] = instance_profile
    if app['user_data']:
        logging.debug('user_data=%s', app['user_data'])
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
    min_size = 0
    max_size = desired_capacity
    logging.debug('creating ASG: %s (%s/%s/%s)',
                  asg_name, min_size, desired_capacity, max_size)
    kwargs = {
        'auto_scaling_group_name': asg_name,
        'launch_configuration_name': asg_name,
        'load_balancer_names': app['elb_names'],
        'health_check_type': 'ELB' if app['elb_names'] else 'EC2',
        'health_check_grace_period': 300,
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

    for p in app['scaling_policies']:
        logging.debug('creating ASG scaling policy: %s', p['policy_name'])
        resp, data = _call(
            'autoscaling', 'PutScalingPolicy',
            auto_scaling_group_name=asg_name,
            policy_name=p['policy_name'],
            scaling_adjustment=p['scaling_adjustment'],
            adjustment_type=p['adjustment_type'],
        )
        resp, data = _call(
            'cloudwatch', 'PutMetricAlarm',
            alarm_name=p['alarm']['alarm_name'],
            comparison_operator=p['alarm']['comparison_operator'],
            evaluation_periods=p['alarm']['evaluation_periods'],
            metric_name=p['alarm']['metric_name'],
            namespace=p['alarm']['namespace'],
            period=p['alarm']['period'],
            statistic=p['alarm']['statistic'],
            threshold=p['alarm']['threshold'],
            dimensions=p['alarm']['dimensions'],
            alarm_actions=[data['PolicyARN']],
        )


def _wait_for_running_instances(app, timestamp, desired_capacity):
    asg_name = '{}-{}-{}'.format(app['env_name'], app['app_name'], timestamp)
    while True:
        healthy = []
        resp, data = _call(
            'autoscaling', 'DescribeAutoScalingGroups',
            auto_scaling_group_names=[asg_name],
        )
        asg = data['AutoScalingGroups'][0]

        if app['elb_names']:
            resp, data = _call(
                'elb', 'DescribeInstanceHealth',
                load_balancer_name=app['elb_names'][0],
                instances=[{'InstanceId': i['InstanceId']}
                           for i in asg['Instances']],
            )

            for i in asg['Instances']:
                i['State'] = 'Invalid'
                for j in data.get('InstanceStates', []):
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
    # logging.debug('service=%s operation=%s', service, operation)
    resp, data = op.call(endpoint, **kwargs)
    # logging.debug('resp=%s data=%s', resp, data)
    return resp, data


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
        'env_name': env_data['env_name']['S'],
        'image_bucket': env_data['image_bucket']['S'],
        'instance_type': app_data['instance_type']['S'],
        'key_name': env_data['key_name']['S'],
        'preferred_availability_zone': env_data[
            'preferred_availability_zone']['S'],
        'vpc_id': env_data['vpc_id']['S'],
    }

    if 'elb_names' in app_data:
        app['elb_names'] = _ddb_parse(app_data['elb_names'])
    else:
        app['elb_names'] = []

    if 'image_id' in app_data:
        app['image_id'] = app_data['image_id']['S']
    else:
        app['image_id'] = ''

    if 'instance_profile_name' in app_data:
        app['instance_profile_name'] = app_data['instance_profile_name']['S']
    else:
        app['instance_profile_name'] = ''

    if 'lifecycle_hooks' in app_data:
        app['lifecycle_hooks'] = _ddb_parse(app_data['lifecycle_hooks'])
    else:
        app['lifecycle_hooks'] = []

    if 'scaling_policies' in app_data:
        app['scaling_policies'] = _ddb_parse(app_data['scaling_policies'])
    else:
        app['scaling_policies'] = []

    if 'logplex_channel_id' in app_data:
        app['logplex_channel_id'] = app_data['logplex_channel_id']['S']
    else:
        app['logplex_channel_id'] = ''

    if 'logplex_token' in app_data:
        app['logplex_token'] = app_data['logplex_token']['S']
    else:
        app['logplex_token'] = ''

    if 'logplex_input_url' in env_data:
        app['logplex_input_url'] = env_data['logplex_input_url']['S']
    else:
        app['logplex_input_url'] = ''

    if 'logplex_url' in env_data:
        app['logplex_url'] = env_data['logplex_url']['S']
    else:
        app['logplex_url'] = ''

    if 'logplex_password' in env_data:
        app['logplex_password'] = env_data['logplex_password']['S']
    else:
        app['logplex_password'] = ''

    if 'logplex_user' in env_data:
        app['logplex_user'] = env_data['logplex_user']['S']
    else:
        app['logplex_user'] = ''

    if 'user_data' in app_data:
        app['user_data'] = app_data['user_data']['S']
    else:
        app['user_data'] = ''

    if 'task_definition' in app_data:
        app['task_definition'] = _ddb_parse(app_data['task_definition'])
    else:
        app['task_definition'] = []

    if 'extra_images' in app_data:
        app['extra_images'] = _ddb_parse(app_data['extra_images'])
    else:
        app['extra_images'] = []

    return app


def _ddb_parse(elem):
    # logging.debug('elem=%s', elem)
    assert isinstance(elem, dict)
    assert len(elem.items()) == 1

    key = elem.keys()[0]
    value = elem.values()[0]

    if key == 'M':
        return dict((k, _ddb_parse(v)) for k, v in value.items())
    elif key == 'L':
        return [_ddb_parse(v) for v in value]
    elif key == 'S':
        return value
    elif key == 'N':
        return int(value)
    elif key == 'BOOL':
        return bool(value)
    return None


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print >> sys.stderr, 'interrupted'
