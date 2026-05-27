# Crowdstrike Starlark integration script
# This demonstrates how to collect instances and vulnerabilities using the proto API
#
# Structure:
#   - main: Entry point that orchestrates the integration
#   - parse_command_line_args: Parses and validates input parameters
#   - get_bearer_token: Gets a bearer token from OAuth endpoint
#   - revoke_bearer_token: Revokes a bearer token
#   - fetch_instances: Fetches device instances from the API
#   - fetch_vulnerabilities: Fetches vulnerability data from the API
#   - get_url_with_params: Builds a URL with query parameters
#   - parse_to_instance: Parses a device object to a zafran protobuf instance message
#   - parse_to_finding: Parses a vulnerability object to a zafran protobuf vulnerability message

load("http", "http")
load("json", "json")
load("log", "log")
load("base64", "base64")
load("zafran", "zafran")
pb = zafran.proto_file


OAUTH_TOKEN_ENDPOINT = "/oauth2/token"
OAUTH_REVOKE_ENDPOINT = "/oauth2/revoke"
COMBINED_DEVICES_ENDPOINT = "/devices/combined/devices/v1"
COMBINED_VULNS_ENDPOINT = "/spotlight/combined/vulnerabilities/v1"
MAX_DEVICES_PER_FLUSH = 50000
MAX_VULNS_PER_FLUSH = 500000
CVSS_VERSION = "3.1"


def parse_command_line_args(kwargs):
    """
    Parse and validate input parameters.
    
    Args:
        kwargs: Dictionary of input parameters
        
    Returns:
        Dictionary with parsed parameters
    """
    api_url = kwargs.get("api_url", None)
    api_key = kwargs.get("api_key", None)
    api_secret = kwargs.get("api_secret", None)
    
    if not api_url:
        log.error("api_url is required")
        return None

    if not api_key:
        log.error("api_key is required")
        return None

    if not api_secret:
        log.error("api_secret is required")
        return None

    return {
        "api_url": api_url,
        "api_key": api_key,
        "api_secret": api_secret
    }


def main(**kwargs):
    """
    Main function for the integration.

    Accepts parameters:
    - api_url: Base URL of the Crowdstrike API
    - api_key: Crowdstrike API authentication key used for token exchange
    - api_secret: Crowdstrike API secret for OAuth token exchange
    """

    # Parse and validate parameters
    parsed_args = parse_command_line_args(kwargs)    
    if parsed_args == None:
        log.error("Failed to parse command line arguments")
        return -1
    
    api_url = parsed_args["api_url"]
    api_key = parsed_args["api_key"]
    api_secret = parsed_args["api_secret"]
    log.debug("Successfully parsed command line arguments")

    log.info("Starting integration with API:", api_url)

    log.info("Getting bearer token via OAuth...")
    bearer_token = get_bearer_token(api_url=api_url, client_id=api_key, client_secret=api_secret)
    if bearer_token == None:
        log.error("Failed to get bearer token")
        return -1
    log.info("Successfully obtained bearer token")

    log.info("Fetching devices and vulnerabilities...")
    device_offset = None
    device_limit = 100
    devices_collected_since_flush = 0
    vulns_collected_since_flush = 0
    while True:
        device_response = fetch_instances(api_url=api_url, limit=device_limit, bearer_token=bearer_token, offset=device_offset)
        if not device_response:
            log.error("Failed to fetch instances")
            return -1

        device_offset = device_response.get("next_offset", None)
        log.debug("Next device offset: " + (device_offset[:10] if device_offset else "None"))
        devices = device_response.get("resources", [])
        if not devices:
            break

        log.debug("Processing " + str(len(devices)) + " devices")
        for device in devices:
            device_proto = parse_to_instance(pb, device)
            if not device_proto:
                log.warning("Failed to parse device: ", device)
                continue
            zafran.collect_instance(device_proto)
            devices_collected_since_flush += 1
            if devices_collected_since_flush >= MAX_DEVICES_PER_FLUSH:
                log.debug("Will flush because of device limit")
                zafran.flush()
                devices_collected_since_flush = 0
                vulns_collected_since_flush = 0

            vuln_offset = None
            vuln_limit = 1000
            while True:
                vuln_response = fetch_vulnerabilities(api_url=api_url, device=device, limit=vuln_limit, bearer_token=bearer_token, offset=vuln_offset)
                if not vuln_response:
                    break

                vuln_offset = vuln_response.get("next_offset", None)
                log.debug("Next vulnerability offset: " + (vuln_offset[:10] if vuln_offset else "None"))
                vulnerabilities = vuln_response.get("resources", [])
                if not vulnerabilities:
                    break
                log.debug("\tProcessing " + str(len(vulnerabilities)) + " vulnerabilities")

                for vulnerability in vulnerabilities:
                    vulnerability_proto = parse_to_finding(pb=pb, raw_vuln=vulnerability)
                    if not vulnerability_proto:
                        log.warn("Failed to parse vulnerability: ", vulnerability)
                        continue
                    zafran.collect_vulnerability(vulnerability_proto)
                    vulns_collected_since_flush += 1
                    if vulns_collected_since_flush >= MAX_VULNS_PER_FLUSH:
                        log.debug("Will flush because of vulnerability limit")
                        zafran.flush()
                        vulns_collected_since_flush = 0
                        devices_collected_since_flush = 0

                if vuln_offset == None:
                    break

        if device_offset == None:
            break

    zafran.flush()
    devices_collected_since_flush = 0
    vulns_collected_since_flush = 0

    log.info("Revoking bearer token...")
    revoke_result = revoke_bearer_token(api_url=api_url, client_id=api_key, client_secret=api_secret, bearer_token=bearer_token)
    if not revoke_result:
        log.error("Failed to revoke bearer token")
    return 0


def get_bearer_token(api_url, client_id, client_secret):
    """
    Get a bearer token from an OAuth endpoint.
    This function exchanges client credentials for an access token.

    Args:
        api_url: Base URL of the API
        client_id: OAuth client ID, the api_key
        client_secret: OAuth client secret

    Returns:
        Bearer token string 
    """
    # Build token endpoint URL
    token_url = "/".join([api_url.rstrip("/"), OAUTH_TOKEN_ENDPOINT.strip("/")])

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    # OAuth client credentials grant payload
    key_value_args = [
        ("client_id", client_id),
        ("client_secret", client_secret)
    ]
    payload = "&".join(["=".join(k_and_v) for k_and_v in key_value_args])

    # Make token request
    response = http.post(token_url, headers=headers, body=payload)
    if not response:
        log.error("Failed to get token: response is None")
        return None

    status = response.get("status_code", None)
    if status not in [200, 201]:
        log.error("Failed to get token, HTTP status code: ", status)
        return None

    body = response.get("body", None)
    if not body:
        log.error("Failed to get token: response body is empty")
        return None

    token_data = json.decode(body)
    if not token_data:
        log.error("Failed to decode token data")
        return None

    token = token_data.get("access_token", None)
    if not token:
        log.error("Failed to get token from response")
        return None
    return token


def revoke_bearer_token(api_url, client_id, client_secret, bearer_token):
    """
    Revoke a bearer token.
    This function revokes the access token.
    
    Args:
        api_url: Base URL of the API
        client_id: OAuth client ID
        client_secret: OAuth client secret
        bearer_token: Bearer token to revoke
        
    Returns:
        True if token was revoked successfully, False otherwise
    """
    # Build revoke endpoint URL
    revoke_url = "/".join([api_url.rstrip("/"), OAUTH_REVOKE_ENDPOINT.strip("/")])
    base64_encoded_credentials = base64.encode(":".join([client_id, client_secret]))
    if not base64_encoded_credentials:
        log.error("Failed to encode credentials")
        return False
    basic_auth_header_payload = "Basic" + " " + base64_encoded_credentials

    headers = {
        "Authorization": basic_auth_header_payload,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    
    # OAuth revoke payload
    key_value_args = [
        ("token", bearer_token)
    ]
    payload = "&".join(["=".join(k_and_v) for k_and_v in key_value_args])

    # Make revoke request
    response = http.post(revoke_url, headers=headers, body=payload)
    if not response:
        log.error("Failed to revoke token: response is None")
        return False
    
    status_code = response.get("status_code", None)
    if status_code != 200:
        log.error("Failed to revoke token, HTTP status code: ", status_code)
        return False
    return True


def fetch_instances(api_url, limit, bearer_token, offset = None, sort = "device_id.asc"):
    """
    Fetch devices from the combined API.

    Args:
        api_url: Base URL of the API
        limit: Number of items per page for pagination
        bearer_token: Bearer token for authentication
        offset: Offset for pagination (optional)
        sort: Sort order for pagination (optional)

    Returns:
        List of raw instance data
    """
    headers = {
        "Authorization": "Bearer " + bearer_token,
        "Accept": "application/json"
    }

    # Build request URL
    params = [("limit", limit)]
    if offset:
        params.append(("offset", offset))
    if sort:
        params.append(("sort", sort))

    url = "/".join([api_url.rstrip("/"), COMBINED_DEVICES_ENDPOINT.strip("/")])
    url = get_url_with_params(url, params)

    # Make API request
    response = http.get(url, headers=headers)
    if not response:
        log.error("Failed to fetch from combined devices API")
        return None

    status_code = response.get("status_code", None)
    body = json.decode(response.get("body", None))
    if status_code != 200:
        log.error("Failed to fetch from combined devices API, status:", status_code)
        return None
    if not body:
        log.error("Failed to fetch from combined devices API, body is missing")
        return None

    next_offset = body.get("meta", {}).get("pagination", {}).get("next", None)
    resources = body.get("resources", [])
    if len(resources) < limit:
        # per the docs, if the number of resources is less than the limit, we've reached the end
        next_offset = None

    return {
        "next_offset": next_offset,
        "resources": resources
    }


def fetch_vulnerabilities(api_url, device, limit, bearer_token, offset = None, sort = "created_timestamp.desc"):
    """
    Fetch vulnerabilities for a device from the combined API.
    
    Args:
        api_url: Base URL of the API
        device: Device object
        limit: Number of items per page for pagination
        offset: Offset for pagination (optional)
        sort: Sort order for pagination (optional)
        
    Returns:
        List of raw vulnerability data
    """
    headers = {
        "Authorization": "Bearer " + bearer_token,
        "Accept": "application/json"
    }
    # Build request URL
    params = [
        ("limit", limit),
        ("filter", "aid:'" + device["device_id"] + "'"),
        ("facet", "remediation"),
        ("facet", "cve"),
    ]
    if offset:
        params.append(("after", offset))
    if sort:
        params.append(("sort", sort))
    url = "/".join([api_url.rstrip("/"), COMBINED_VULNS_ENDPOINT.strip("/")])
    url = get_url_with_params(url, params)

    # Make API request
    response = http.get(url, headers=headers)
    if not response:
        log.error("Failed to fetch from combined vulnerabilites API")
        return None

    status_code = response.get("status_code", None)
    body = json.decode(response.get("body", None))

    if status_code != 200:
        log.error("Failed to fetch from combined vulnerabilites API, status:", status_code)
        return None
    if not body:
        log.error("Failed to fetch from combined vulnerabilites API, body is missing")
        return None
    next_offset = body.get("meta", {}).get("pagination", {}).get("after", None)
    resources = body.get("resources", [])

    if len(resources) < limit:
        # per the docs, if the number of resources is less than the limit, we've reached the end
        next_offset = None

    return {
        "next_offset": next_offset,
        "resources": resources
    }


def get_url_with_params(url, params):
    """
    Build a URL with query parameters.
    
    Args:
        url: Base URL
        params: Dictionary of query parameters
        
    Returns:
        URL with query parameters
    """
    if not params:
        return url
    if not url:
        return url

    # Build query string
    query_parts = []
    for key, value in params:
        query_parts.append("=".join([str(key), str(value)]))
    
    query_string = "&".join(query_parts)
    
    # Add query string to URL
    separator = "&" if "?" in url else "?"
    return "".join([url, separator, query_string])


def parse_to_instance(pb, raw_instance):
    """
    Parse raw asset data into an InstanceData proto message.

    Args:
        raw_instance: Raw instance dict from the API
        pb: Proto types from zafran.proto_file

    Returns:
        InstanceData proto message
    """
    instance_id = raw_instance.get("instance_id", None)
    if not instance_id:
        log.warning("Instance missing ID")
        return None

    # Extract fields from raw data
    hostname = raw_instance.get("hostname", "")
    os = raw_instance.get("os_build", "")
    ip = raw_instance.get("external_ip", None)
    mac = raw_instance.get("mac_address", None)

    instance_identifiers = []
    if "AWS_EC2" in raw_instance.get("service_provider", ""):
        instance_identifiers.append(pb.InstanceIdentifier(
            key=pb.IdentifierType.AWS_EC2_INSTANCE_ID,
            value=instance_id
        ))
        instance_type = pb.InstanceType.INSTANCE_TYPE_MACHINE
    else:
        instance_identifiers.append(pb.InstanceIdentifier(
            key=pb.IdentifierType.IDENTIFIER_TYPE_UNSPECIFIED,
            value=instance_id
        ))
        instance_type = pb.InstanceType.INSTANCE_TYPE_UNKNOWN

    labels = raw_instance.get("labels", [])
    # I don't know how I am supposed to create a protobuf Timestamp object
    # it is not in the example and what I tried did not work
    # last_seen = raw_instance.get("last_seen", None)
    # Create and return the InstanceData proto
    return pb.InstanceData(
        instance_id=instance_id,
        name=hostname,
        operating_system=os,
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=[ip] if ip else [],
            mac_addresses=[mac] if mac else []
        ),
        identifiers=instance_identifiers,
        labels=[pb.InstanceLabel(
            label=label
        ) for label in labels],
        # source_last_seen=last_seen,
        instance_type=instance_type
    )


def parse_to_finding(pb, raw_vuln):
    """
    Parse raw vulnerability data into a Vulnerability proto message.

    Args:
        raw_vuln: Raw vulnerability dict from the API
        pb: Proto types from zafran.proto_file

    Returns:
        Vulnerability proto message
    """
    # Extract fields from raw data
    instance_id = raw_vuln.get("aid", None)
    if not instance_id:
        log.warn("Vulnerability missing instance ID, skipping")
        return None

    cve = raw_vuln.get("cve", {})
    cve_id = cve.get("id", None)
    if not cve_id:
        log.warn("Vulnerability missing CVE")
        return None
    cwe_ids = []
    for cwe_id in cve.get("cwes", []):
        split = cwe_id.split("-")
        if len(split) != 2:
            continue
        cwe_ids.append(int(split[1]))

    description = raw_vuln.get("description", "")
    component = pb.Component(
        product="",
        vendor="",
        version="",
        type=pb.ComponentType.COMPONENT_TYPE_UNSPECIFIED
    )
    apps = raw_vuln.get("apps", [])
    if len(apps):
        component = pb.Component(
            product=apps[0].get("product_name_normalized", ""),
            vendor=apps[0].get("vendor_normalized", ""),
            version=apps[0].get("product_name_version", ""),
            type=pb.ComponentType.APPLICATION
        )

    data_providers = raw_vuln.get("data_providers", [])
    data_provider = (data_providers[0] if len(data_providers) else {}).get("provider")

    remediation = pb.Remediation(
        suggestion="",
        source="",
        fixed_in_version=""
    )
    remediation_entities = raw_vuln.get("remediation", {}).get("entities", [])
    if len(remediation_entities) > 0:
        remediation = pb.Remediation(
            suggestion=remediation_entities[0].get("action", ""),
            source=remediation_entities[0].get("link", ""),
            fixed_in_version=remediation_entities[0].get("patch_publication_date", "")
        )

    return pb.Vulnerability(
        instance_id=instance_id,
        cve=cve_id,
        cwe_ids=cwe_ids,
        description=description,
        in_runtime=True,
        component=component,
        CVSS=[
            pb.CVSS(
                version=CVSS_VERSION,
                vector=cve.get("vector", ""),
                base_score=cve.get("base_score", ""),
                source=data_provider,
                type=""
            )
        ],
        remediation=remediation,
        severity=cve.get("severity", ""),
    )
