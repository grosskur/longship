# Longship

Cloud-native application management tool for AWS.

```bash
$ longship push
```

## Overview

Longship ties together a myriad of AWS features including elastic load
balancers, auto-scaling groups, launch configurations, and security
groups to present a simple "application" abstraction.

Longship is a lean tool. It aims to provide the usability of PaaS
without the operational burden of running a PaaS.

Longship stores data in DynamoDB.

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
    list           show list of apps
    info           show details about an app
    upload         build and upload an Docker image
    build          build an AMI from Docker images
    deploy         deploy an AMI into an auto-scaling group
    push           runs upload, build, and deploy in sequence
    log            tail logs for an app
    cleanup        remove old unused auto-scaling groups

Globally recognized options:
    -v, --verbose  verbose output
```

## Acknowledgements

* [The Twelve-Factor App][12factor]
* [Phoenix server][fowler-phoenix-server]
* [Immutable server][fowler-immutable-server]
* [Asgard][asgard-github] ([blog post][asgard-blog-post])
* [Aminator][aminator-github] ([blog post][aminator-blog-post])
* [Packer][packer-github]
* [amzn-ship][amzn-ship-github] ([Application Platforms on AWS][r32k-app-platforms])
* ionblaster ([DockerCon talk][gilt-dockercon-talk])

[12factor]: http://12factor.net/
[aminator-blog-post]: http://techblog.netflix.com/2013/03/ami-creation-with-aminator.html
[aminator-github]: https://github.com/Netflix/aminator
[amzn-ship-github]: https://github.com/ryandotsmith/amzn-ship
[asgard-blog-post]: http://techblog.netflix.com/2012/06/asgard-web-based-cloud-management-and.html
[asgard-github]: https://github.com/Netflix/asgard
[fowler-phoenix-server]: http://martinfowler.com/bliki/PhoenixServer.html
[fowler-immutable-server]: http://martinfowler.com/bliki/ImmutableServer.html
[gilt-dockercon-talk]: https://www.youtube.com/watch?v=GaHzdqFithc
[packer-github]: https://github.com/mitchellh/packer
[r32k-app-platforms]: http://r.32k.io/app-platforms-on-aws
