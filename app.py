from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import logging
import warnings
from urllib3.exceptions import InsecureRequestWarning
import os
import threading
import time
from datetime import datetime, timedelta

warnings.simplefilter('ignore', InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel(logging.INFO)  # Set to INFO for better debugging

# ================= New section for automatic token refresh =================
# Configuration
ACCOUNTS_FILE = "accounts.txt"          # File containing uid:password lines
TOKEN_FILE_BD = "token_bd.json"          # Token file to update
TOKEN_REFRESH_INTERVAL_HOURS = 2         # Refresh tokens every 2 hours
TOKEN_API_URL = "https://papajwt.vercel.app/kirito"  # Token API endpoint

def load_accounts_from_file():
    """
    Reads uid:password pairs from accounts.txt.
    Each line should be in the format uid:password.
    Returns a list of dicts [{'uid': '...', 'password': '...'}, ...].
    """
    accounts = []
    try:
        if not os.path.exists(ACCOUNTS_FILE):
            app.logger.error(f"Accounts file {ACCOUNTS_FILE} not found.")
            return accounts
        
        with open(ACCOUNTS_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):  # Skip empty lines and comments
                    continue
                if ":" not in line:
                    app.logger.warning(f"Line {line_num}: Invalid format (expected uid:password). Skipping.")
                    continue
                uid, password = line.split(":", 1)
                accounts.append({
                    "uid": uid.strip(),
                    "password": password.strip()
                })
        app.logger.info(f"Loaded {len(accounts)} accounts from {ACCOUNTS_FILE}.")
    except Exception as e:
        app.logger.error(f"Error loading accounts file: {e}")
    return accounts

def fetch_token_from_api(uid, password):
    """
    Calls the token API with the given uid and password.
    On success, returns {'uid': account_uid, 'token': jwt_token, 'region': region}.
    On failure, returns None.
    """
    try:
        params = {
            "uid": uid,
            "password": password
        }
        response = requests.get(TOKEN_API_URL, params=params, timeout=30)
        response.raise_for_status()  # Raise HTTPError for bad responses
        
        data = response.json()
        app.logger.debug(f"API response: {data}")
        
        if data.get("status") == "success":
            account_uid = data.get("account_uid") or data.get("uid")
            jwt_token = data.get("jwt_token")
            region = data.get("region")
            
            if account_uid and jwt_token and region:
                return {
                    "uid": str(account_uid),
                    "token": jwt_token,
                    "region": region
                }
            else:
                app.logger.error(f"Required fields missing in response: {data}")
        else:
            app.logger.error(f"API returned status '{data.get('status')}' instead of 'success'.")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API request failed (UID: {uid}): {e}")
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to parse API response JSON (UID: {uid}): {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error (UID: {uid}): {e}")
    return None

def update_token_json(new_accounts_data):
    """
    Updates token_bd.json with new account data.
    If the file already exists, merges with existing data (overwrites duplicate UIDs).
    Creates a backup of the old file.
    """
    try:
        existing_data = []
        # Read existing file if present
        if os.path.exists(TOKEN_FILE_BD):
            with open(TOKEN_FILE_BD, "r") as f:
                try:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        app.logger.warning(f"{TOKEN_FILE_BD} is not a list. Creating new file.")
                        existing_data = []
                except json.JSONDecodeError:
                    app.logger.warning(f"{TOKEN_FILE_BD} is corrupted or empty. Creating new file.")
                    existing_data = []
        
        # Merge by UID (new entries overwrite old ones)
        uid_to_existing = {item["uid"]: item for item in existing_data}
        for new_item in new_accounts_data:
            uid_to_existing[new_item["uid"]] = new_item
        
        merged_data = list(uid_to_existing.values())
        
        # Backup old file (optional)
        if os.path.exists(TOKEN_FILE_BD):
            backup_file = f"{TOKEN_FILE_BD}.backup"
            try:
                os.rename(TOKEN_FILE_BD, backup_file)
                app.logger.info(f"Backup created: {backup_file}")
            except Exception as e:
                app.logger.warning(f"Failed to create backup: {e}")
        
        # Write updated data
        with open(TOKEN_FILE_BD, "w") as f:
            json.dump(merged_data, f, indent=2)
        
        app.logger.info(f"{TOKEN_FILE_BD} updated successfully with {len(merged_data)} entries.")
        return True
    except Exception as e:
        app.logger.error(f"Failed to update token file: {e}")
        return False

def refresh_all_tokens():
    """
    Main function to refresh tokens for all accounts in accounts.txt.
    Called periodically by the scheduler.
    """
    app.logger.info("Starting token refresh process...")
    accounts = load_accounts_from_file()
    if not accounts:
        app.logger.warning("No accounts found. Token refresh aborted.")
        return
    
    successful_accounts = []
    failed_count = 0
    
    for idx, acc in enumerate(accounts, 1):
        app.logger.info(f"[{idx}/{len(accounts)}] Fetching token for UID: {acc['uid']}...")
        result = fetch_token_from_api(acc['uid'], acc['password'])
        if result:
            successful_accounts.append(result)
            app.logger.info(f"  -> Success! UID: {result['uid']}, Region: {result['region']}")
        else:
            failed_count += 1
            app.logger.error(f"  -> Failed for UID: {acc['uid']}")
        
        # Small delay to avoid hitting API rate limits
        time.sleep(0.5)
    
    if successful_accounts:
        update_token_json(successful_accounts)
        app.logger.info(f"Token refresh finished. Success: {len(successful_accounts)}, Failed: {failed_count}")
    else:
        app.logger.error("No tokens were successfully fetched. File not updated.")

def scheduled_token_refresh():
    """
    Scheduler loop that runs refresh_all_tokens() every TOKEN_REFRESH_INTERVAL_HOURS.
    Runs in a separate daemon thread.
    """
    while True:
        next_run = datetime.now() + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)
        app.logger.info(f"Next token refresh scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Run the refresh
        refresh_all_tokens()
        
        # Wait until next interval
        time.sleep(TOKEN_REFRESH_INTERVAL_HOURS * 3600)

def start_background_scheduler():
    """
    Starts the scheduler thread when the Flask app starts.
    """
    scheduler_thread = threading.Thread(target=scheduled_token_refresh, daemon=True)
    scheduler_thread.start()
    app.logger.info("Token refresh scheduler started in background.")
# ================= End of new section =================

# Original functions remain unchanged (with English comments where necessary)

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Token load failed: {server_name}. Error: {e}") 
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encryption failed. Error: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation (like) failed. Error: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed: Status {response.status}") 
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"send_request exception: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Like protobuf failed.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Like encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Token load failed in multi-send.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"send_multiple_requests exception: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation (uid) failed. Error: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False) 
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decode failed in make_request.")
        return decode
    except Exception as e:
        app.logger.error(f"make_request exception: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"DecodeError: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Decode failed: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            tokens = load_tokens(server_name)
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"'before' proto to JSON failed: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            
            app.logger.info(f"Initial likes: {before_like}") 

            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"'after' proto to JSON failed: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            result = {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Main request processing failed: {e}")
        return jsonify({"error": str(e)}), 500

# ================= Start background scheduler and run app on all interfaces =================
if __name__ == '__main__':
    # Start the token refresh scheduler in background
    start_background_scheduler()
    # Run Flask app on all available IPs, port 5000 (default)
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True, threaded=True)