#!/usr/bin/python3

from sys import exit
import os

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'jg-skunkworks-641aebdfbb4f.json'


def deidentify_with_det (
    project,
    input_str,
    info_types,
    surrogate_type=None,
    key_name="projects/jg-skunkworks/locations/global/keyRings/dlp-keyring/cryptoKeys/dlp-key",
    wrapped_key="CiQAOqKojrL9JXFhK3RY/8F6Pnmt6XXiPzffmY1OD4VaeS9emkQSSQD6od+dmqvlgEjBSaUW/YnrnWwP3AwLBLVTNUsbNcrJlIbBXKljYkGzYFW48JA++l+YvDdwqB+N2wDI97Azt6iuw2cd+QB2NIU="
):
    """Uses the Data Loss Prevention API to deidentify sensitive data in a
    string using Format Preserving Encryption (FPE).
    Args:
        project: The Google Cloud project id to use as a parent resource.
        input_str: The string to deidentify (will be treated as text).
        surrogate_type: The name of the surrogate custom info type to use. Only
            necessary if you want to reverse the deidentification process. Can
            be essentially any arbitrary string, as long as it doesn't appear
            in your dataset otherwise.
        key_name: The name of the Cloud KMS key used to encrypt ('wrap') the
            AES-256 key. Example:
            key_name = 'projects/YOUR_GCLOUD_PROJECT/locations/YOUR_LOCATION/
            keyRings/YOUR_KEYRING_NAME/cryptoKeys/YOUR_KEY_NAME'
        wrapped_key: The encrypted ('wrapped') AES-256 key to use. This key
            should be encrypted using the Cloud KMS key specified by key_name.
    Returns:
        None; the response from the API is printed to the terminal.
    """
    # Import the client library
    import google.cloud.dlp

    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # The wrapped key is base64-encoded, but the library expects a binary
    # string, so decode it here.
    import base64

    wrapped_key = base64.b64decode(wrapped_key)

    # Construct configuration dictionary
    crypto_deterministic_config = {
        "crypto_key": {
            "kms_wrapped": {"wrapped_key": wrapped_key, "crypto_key_name": key_name}
        }
    }

    # Add surrogate type
    if surrogate_type:
        crypto_deterministic_config["surrogate_info_type"] = {"name": surrogate_type}

    # Construct inspect configuration dictionary
    inspect_config = {"info_types": [{"name": info_type} for info_type in info_types]}

    # Construct deidentify configuration dictionary
    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {
                    "primitive_transformation": {
                        "crypto_deterministic_config": crypto_deterministic_config
                    }
                }
            ]
        }
    }

    # Convert string to item
    item = {"value": input_str}
    request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item,
	}

    print("DEBUG: ", request)

    # Call the API
    response = dlp.deidentify_content(request)

    # Print results
    return(response.item.value)



### MAIN ###
infotypes = ['PERSON_NAME']
rows = [
    "Ainsley Wilson",
    "Colby Morin",
    "Cherokee Vinson",
    "Ferdinand Gilmore",
    "Mia Robbins"]

for row in rows:
   print("NAME = %s" % (row))
   print(deidentify_with_det(project='jg-skunkworks',input_str=row,info_types=infotypes,surrogate_type="NAME_TOKEN"))
