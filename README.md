# Longship

Cloud-native application management tool for AWS.

```bash
$ longship init prod
$ longship create --env prod myapp
$ longship upload
$ longship build
$ longship deploy
$ longship cleanup
$ longship set FOO=bar
$ longship unset FOO
$ longship scale web=2 worker=1
$ longship web=t2.medium worker=m3.large
$ longship tail -f
```

## Overview

Longship ties together a myriad of AWS features including elastic load
balancers, auto-scaling groups, launch configurations, and security
groups to present a simple "application" abstraction.

Longship is a lean tool. It aims to provide the usability of PaaS
without the operational burden of running a PaaS.

## How it works

Longship manages AWS resources as immutable infrastructure.

1. Upload a Docker image to S3.
2. Build the Docker image into an AMI.
3. Create a new launch configuration for each process type, injecting
   the environment variables and Docker command line via user-data.
4. Create a new autoscaling group for each launch configuration, bring
   it into service, and decommision the old autoscaling group.

## Command line reference

```bash
usage: longship [--version] [--help] <command> [<args>]

Cloud-native application management tool for AWS

Available commands:
    init           initialize region for running apps
    topology       show network topology in region
    apps           show list of apps
    create         create a new app
    info           show details about an app
    tail           view logs for an app
    env            show environment variables for an app
    set            set environment variables for an app
    unset          unset environment variables for an app
    build          build an AMI from an app image
    deploy         deploy an AMI into an auto-scaling group
    releases       show list of releases for an app
    rollback       rollback to a prior AMI
    cleanup        remove old unused auto-scaling groups
    ps             list process types for an app
    scale          change the instance count for a process type
    resize         change the instance type for a process type
    policy         show IAM policy for an app
    destroy        destroy an app
    nuke           destroy all apps and metadata in a region

Globally recognized options:
    -v, --verbose  verbose output
```

## Acknowledgements

* The Twelve-Factor App
* Asgard (blog post)
* Aminator (blog post)
* Packer
* amzn-ship (Application Platforms on AWS)
* ionblaster (DockerCon talk)

http://techblog.netflix.com/2012/06/asgard-web-based-cloud-management-and.html
http://techblog.netflix.com/2013/03/ami-creation-with-aminator.html
http://martinfowler.com/bliki/PhoenixServer.html
http://martinfowler.com/bliki/ImmutableServer.html
