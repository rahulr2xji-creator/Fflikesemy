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
app.logger.setLevel(logging.INFO)  # CRITICAL থেকে INFO করা হয়েছে ডিবাগিংয়ের জন্য

# ================= নতুন অংশ শুরু =================
# কনফিগারেশন
ACCOUNTS_FILE = "accounts.txt"          # uid:password ফরম্যাটের ফাইল
TOKEN_FILE_BD = "token_bd.json"          # আপডেট হবে এই ফাইল
TOKEN_REFRESH_INTERVAL_HOURS = 2         # প্রতি ২ ঘণ্টা পর পর
TOKEN_API_URL = "https://rizerxguestaccountacceee.vercel.app//rizer"  # টোকেন সংগ্রহের API

def load_accounts_from_file():
    """
    accounts.txt ফাইল থেকে uid:password জোড়া পড়ে একটি লিস্ট রিটার্ন করে।
    ফরম্যাট: প্রতিটি লাইনে uid:password
    """
    accounts = []
    try:
        if not os.path.exists(ACCOUNTS_FILE):
            app.logger.error(f"{ACCOUNTS_FILE} The file was not found.")
            return accounts
        
        with open(ACCOUNTS_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):  # খালি লাইন বা কমেন্ট ইগনোর
                    continue
                if ":" not in line:
                    app.logger.warning(f"Line {line_num}: Invalid format (expected uid:password). Skipping.")
                    continue
                uid, password = line.split(":", 1)
                accounts.append({
                    "uid": uid.strip(),
                    "password": password.strip()
                })
        app.logger.info(f"Total {len(accounts)}T accounts loaded {ACCOUNTS_FILE} From।")
    except Exception as e:
        app.logger.error(f"Problem loading account file: {e}")
    return accounts

def fetch_token_from_api(uid, password):
    """
    প্রদত্ত uid এবং password দিয়ে টোকেন API-তে কল করে।
    সফল হলে {'uid': account_uid, 'token': jwt_token, 'region': region} রিটার্ন করে।
    ব্যর্থ হলে None রিটার্ন করে।
    """
    try:
        params = {
            "uid": uid,
            "password": password
        }
        response = requests.get(TOKEN_API_URL, params=params, timeout=30)
        response.raise_for_status()  # HTTP এরর চেক
        
        data = response.json()
        app.logger.debug(f"API রেসপন্স: {data}")
        
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
                app.logger.error(f"Required field is missing. Response: {data}")
        else:
            app.logger.error(f"API 'success' Did not return. Status: {data.get('status')}")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API Request bar্থ (UID: {uid}): {e}")
    except json.JSONDecodeError as e:
        app.logger.error(f"API Response JSON Parse failed. (UID: {uid}): {e}")
    except Exception as e:
        app.logger.error(f"Unknown error (UID: {uid}): {e}")
    return None

def update_token_json(new_accounts_data):
    """
    নতুন অ্যাকাউন্ট ডেটা দিয়ে token_bd.json আপডেট করে।
    যদি ফাইল আগে থেকে থাকে, তবে পুরাতন ডেটার সাথে মার্জ করে।
    ডুপ্লিকেট UID থাকলে নতুন ডেটা দিয়ে পুরাতন ডেটা প্রতিস্থাপন করে।
    """
    try:
        existing_data = []
        # আগের ফাইল পড়ার চেষ্টা
        if os.path.exists(TOKEN_FILE_BD):
            with open(TOKEN_FILE_BD, "r") as f:
                try:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        app.logger.warning(f"{TOKEN_FILE_BD} Format is incorrect (list was expected). New file will be created.।")
                        existing_data = []
                except json.JSONDecodeError:
                    app.logger.warning(f"{TOKEN_FILE_BD} Could not be read (probably empty or corrupt). A new file will be created.।")
                    existing_data = []
        
        # নতুন ডেটা মার্জ (UID অনুযায়ী ডুপ্লিকেট রিমুভ)
        uid_to_existing = {item["uid"]: item for item in existing_data}
        for new_item in new_accounts_data:
            uid_to_existing[new_item["uid"]] = new_item  # নতুন ডেটা দিয়ে ওভাররাইট
        
        merged_data = list(uid_to_existing.values())
        
        # ব্যাকআপ হিসেবে পুরাতন ফাইল রাখা (ঐচ্ছিক)
        if os.path.exists(TOKEN_FILE_BD):
            backup_file = f"{TOKEN_FILE_BD}.backup"
            try:
                os.rename(TOKEN_FILE_BD, backup_file)
                app.logger.info(f"Old files backed up: {backup_file}")
            except Exception as e:
                app.logger.warning(f"Failed to backup: {e}")
        
        # নতুন ফাইল লেখা
        with open(TOKEN_FILE_BD, "w") as f:
            json.dump(merged_data, f, indent=2)
        
        app.logger.info(f"{TOKEN_FILE_BD} Updated successfully. Total {len(merged_data)}There are 3 entries.")
        return True
    except Exception as e:
        app.logger.error(f"Failed to update token file: {e}")
        return False

def refresh_all_tokens():
    """
    মূল ফাংশন যা accounts.txt থেকে সব একাউন্টের জন্য টোকেন রিফ্রেশ করে।
    আলাদা থ্রেডে চলে।
    """
    app.logger.info("Token refresh process started...")
    accounts = load_accounts_from_file()
    if not accounts:
        app.logger.warning("No account found. Token refresh canceled.")
        return
    
    successful_accounts = []
    failed_count = 0
    
    for idx, acc in enumerate(accounts, 1):
        app.logger.info(f"[{idx}/{len(accounts)}] UID: {acc['uid']} Tokens are being collected for this...")
        result = fetch_token_from_api(acc['uid'], acc['password'])
        if result:
            successful_accounts.append(result)
            app.logger.info(f"  -> Successful! UID: {result['uid']}, Region: {result['region']}")
        else:
            failed_count += 1
            app.logger.error(f"  -> Failed: UID: {acc['uid']}")
        
        # API-তে চাপ কমানোর জন্য ছোট বিরতি (ঐচ্ছিক)
        time.sleep(0.5)
    
    if successful_accounts:
        update_token_json(successful_accounts)
        app.logger.info(f"Token refresh completed. Successful: {len(successful_accounts)}, Failed: {failed_count}")
    else:
        app.logger.error("No tokens were successfully collected. File not updated.।")

def scheduled_token_refresh():
    """
    নির্দিষ্ট সময় পর পর টোকেন রিফ্রেশ করার জন্য শিডিউলার ফাংশন।
    এটি একটি ইনফিনিট লুপে চলে এবং প্রতি INTERVAL ঘণ্টা পর পর refresh_all_tokens() কল করে।
    """
    while True:
        next_run = datetime.now() + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)
        app.logger.info(f"The next token refresh will be: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # প্রথমবার রান
        refresh_all_tokens()
        
        # পরবর্তী রানের জন্য অপেক্ষা
        time.sleep(TOKEN_REFRESH_INTERVAL_HOURS * 3600)

def start_background_scheduler():
    """
    ব্যাকগ্রাউন্ডে শিডিউলার থ্রেড শুরু করে।
    Flask অ্যাপ স্টার্ট হওয়ার সময় এই ফাংশন কল করতে হবে।
    """
    scheduler_thread = threading.Thread(target=scheduled_token_refresh, daemon=True)
    scheduler_thread.start()
    app.logger.info("The token refresh scheduler has started in the background.")
# ================= নতুন অংশ শেষ =================

# পুরাতন ফাংশনগুলো অপরিবর্তিত (load_tokens, encrypt_message, create_protobuf_message, send_request, send_multiple_requests, create_protobuf, enc, make_request, decode_protobuf)

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

# ================= নতুন অংশ: অ্যাপ স্টার্ট হলে ব্যাকগ্রাউন্ড শিডিউলার চালু করা =================
if __name__ == '__main__':
    # প্রোডাকশনে ডিবাগ=False এবং থ্রেডেড=True ব্যবহার করা ভালো
    start_background_scheduler()  # ব্যাকগ্রাউন্ডে টোকেন রিফ্রেশ শুরু
    app.run(debug=True, use_reloader=True, threaded=True)