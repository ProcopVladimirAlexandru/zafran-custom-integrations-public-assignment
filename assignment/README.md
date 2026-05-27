# Crowdstrike Integration Script

This directory contains a Starlark script that demonstrates how to build a custom integration with Crowdstrike.

The script should be run exactly as `example.star`, see the associated documentation for details.
Running from root of the project (adapt executable according to your platform):

```bash
./starlark-runner-linux -script ./assignment/assignment.star -params "api_url=https://api.us-2.crowdstrike.com,api_key=7d1...,api_secret=FZ1..."
```

The script iterates through a paginated devices endpoint (`/devices/combined/devices/v1`), adds each device as an instance then for each device it fetches pages of vulnerabilities from `/spotlight/combined/vulnerabilities/v1` endpoint which it then also adds as findings.