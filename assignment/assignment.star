# Crowdstrike Starlark integration script
# This demonstrates how to collect instances and vulnerabilities using the proto API
#
# Structure:
#   - main: Entry point that orchestrates the integration
#   - get_bearer_token: (Optional) Gets a bearer token from OAuth endpoint
#


load("http", "http")
load("json", "json")
load("log", "log")
# load("zafran", "zafran")


OAUTH_TOKEN_ENDPOINT = "/oauth2/token"


def parse_params(kwargs):
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
    parsed_params = parse_params(kwargs)    
    if parsed_params == None:
        log.error("Failed to parse parameters")
        return -1
    
    api_url = parsed_params["api_url"]
    api_key = parsed_params["api_key"]
    api_secret = parsed_params["api_secret"]
    log.debug("Successfully parsed parameters")

    log.info("Starting integration with API:", api_url)

    # Step 0: Get bearer token
    log.info("Step 0: Getting bearer token via OAuth...")
    bearer_token = get_bearer_token(api_url, api_key, api_secret)
    if bearer_token == None:
        log.error("Failed to get bearer token")
        return -1
    log.info("Successfully obtained bearer token")
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

    if response.get("status_code") not in [200, 201]:
        log.error("Failed to get token, HTTP status code: ", response["status_code"])
        return None

    if not response.get("body", None):
        log.error("Failed to get token: response body is empty")
        return None

    token_data = json.decode(response["body"])
    token = token_data.get("access_token", None)
    if not token:
        log.error("Failed to get token from response")
        return None
    return token
