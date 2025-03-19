import requests
import json

def perform_login(username, password):
    """
    Performs a login request to the API and returns the response.

    Args:
        username (str): The username for login.
        password (str): The password for login.

    Returns:
        dict or None: The JSON response from the API if successful, None otherwise.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Login"
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "id": 99,
        "params": {
            "user": username,
            "password": password
        }
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()  # Return the JSON response
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None

def create_user(user_data):
    """
    Creates a new user via a POST request to the /celepar/Admin/CreateUser endpoint.

    Args:
        user_data (dict): A dictionary containing the user's information 
                          (auth, accountLogin, accountEmail, accountName, accountProfile, accountPassword).

    Returns:
        The JSON response from the API if successful, None otherwise.
    """
    url = "https://api-slim.expresso.pr.gov.br/celepar/Admin/CreateUser"
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "id": 64,  # The ID is fixed as per the cURL command
        "params": user_data
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()  # Return the JSON response
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None

# Example usage (Login and then Create User):
username = "*"
password = "*"

login_response = perform_login(username, password)
auth = None

if login_response:
    print("Login API Response:")
    print(json.dumps(login_response, indent=2, ensure_ascii=False))

    # **Diagnostic Step 1: Print all keys in the response**
    print("\nKeys in Login Response:")
    for key in login_response.keys():
        print(f"- {key}")
    
    # **Diagnostic Step 2: Check if 'auth' is in the response**
    if "auth" in login_response:
        print("\n'auth' key is present in the response.")
    else:
        print("\n'auth' key is NOT present in the response.")

    # **Diagnostic Step 3: Check if 'result' is in the response**
    if "result" in login_response:
        print("\n'result' key is present in the response.")
        if "auth" in login_response["result"]:
            print("\n'auth' key is present in the result of the response.")
            auth = login_response["result"]["auth"]
        else:
            print("\n'auth' key is NOT present in the result of the response.")
    else:
        print("\n'result' key is NOT present in the response.")

    # **Diagnostic Step 4: Check if 'data' is in the response**
    if "data" in login_response:
        print("\n'data' key is present in the response.")
        if "auth" in login_response["data"]:
            print("\n'auth' key is present in the data of the response.")
            auth = login_response["data"]["auth"]
        else:
            print("\n'auth' key is NOT present in the data of the response.")
    else:
        print("\n'data' key is NOT present in the response.")

    # **Diagnostic Step 5: Check if 'token' is in the response**
    if "token" in login_response:
        print("\n'token' key is present in the response.")
        auth = login_response["token"]
    else:
        print("\n'token' key is NOT present in the response.")

    # **Diagnostic Step 6: Check if 'message' is in the response**
    if "message" in login_response:
        print("\n'message' key is present in the response.")
        print(f"Message: {login_response['message']}")
    else:
        print("\n'message' key is NOT present in the response.")

    # **Diagnostic Step 7: Check if 'success' is in the response**
    if "success" in login_response:
        print("\n'success' key is present in the response.")
        print(f"Success: {login_response['success']}")
    else:
        print("\n'success' key is NOT present in the response.")

    if auth:
        print(f"\nAuth value: {auth}")

        # Example usage for create_user (now using the obtained auth):
        user_info = {
            "auth": auth,  # Use the auth value obtained from the login
            "accountLogin": "*",
            "accountEmail": "*",
            "accountName": "*", # nome
            "accountProfile": "*", # sobrenome
            "accountPassword": "*"
        }

        api_response_create_user = create_user(user_info)

        if api_response_create_user:
            print("\nAPI Response (Create User):")
            print(json.dumps(api_response_create_user, indent=2, ensure_ascii=False))
        else:
            print("\nFailed to create user.")
    else:
        print("\n'auth' key not found in the API response. Cannot create user.")
else:
    print("Login failed.")