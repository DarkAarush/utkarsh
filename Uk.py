import requests
import json
import base64
import time
import re
import os
import string
from termcolor import colored
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from concurrent.futures import ThreadPoolExecutor

COOKIES = (
    "_fbp=...; csrf_name=263666f6f; ..."
)
CSRF_TOKEN = "26f"
TIMEOUT = 10
MAX_WORKERS = 8

TILES_URL = "https://online.utkarsh.com/web/Course/tiles_data"
LAYER2_URL = "https://online.utkarsh.com/web/Course/get_layer_two_data"

KEY = b'%!$!%_$&!%F)&^!^'
IV = b'#*y*#2yJ*#$wJv*v'

TELEGRAM_BOT_TOKEN = "545W4w"
TELEGRAM_CHANNEL_ID = "-1742"

def send_file_telegram(channel_id, token, file_path, caption):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    with open(file_path, "rb") as f:
        files = {"document": (os.path.basename(file_path), f)}
        data = {
            "chat_id": channel_id,
            "caption": caption,
            "parse_mode": "HTML"
        }
        resp = requests.post(url, files=files, data=data)
        if resp.status_code == 200:
            print(colored("✅ Sent to Telegram!", "green"))
            return True
        else:
            print(colored(f"❌ Telegram Error: {resp.text}", "red"))
            return False

def sanitize_filename(filename):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    name = ''.join(c for c in filename if c in valid_chars)
    return name.replace(' ', '_')

def decrypt(enc_text: str) -> str:
    data = base64.b64decode(enc_text)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = unpad(cipher.decrypt(data), AES.block_size)
    return plaintext.decode('utf-8')

def get_headers() -> dict:
    return {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://online.utkarsh.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Cookie': COOKIES,
    }

def ask_batch_ids() -> list:
    raw = input("Enter Batch ID(s) (comma separated): ").strip()
    return [bid.strip() for bid in raw.split(',') if bid.strip().isdigit()]

def fetch_subjects(batch_id: int, headers: dict) -> list:
    payload = {
        "course_id": str(batch_id),
        "revert_api": "1#0#0#1",
        "parent_id": "0",
        "tile_id": "0",
        "layer": "1",
        "type": "course_combo"
    }
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    enc = base64.b64encode(cipher.encrypt(pad(json.dumps(payload).encode(), AES.block_size))).decode()
    resp = requests.post(TILES_URL, headers=headers, data={'tile_input': enc, 'csrf_name': CSRF_TOKEN}, timeout=TIMEOUT)
    data = resp.json().get('response', '')
    data = data.replace('MDE2MTA4NjQxMDI3NDUxNQ==', '==').replace(':', '==')
    return json.loads(decrypt(data)).get('data', [])

def process_layer3_videos(data, links):
    video_list = data.get("data", {}).get("list", [])
    for item in video_list:
        if item.get("payload", {}).get("tile_type") == "video":
            title = item.get("title", "Untitled")
            thumb_url = item.get("thumbnail_url", "")
            vid_id = item.get("id", "")
            yt_match = re.search(r"i\.ytimg\.com/vi/([a-zA-Z0-9_-]{11})/", thumb_url)
            if yt_match:
                yt_code = yt_match.group(1)
                yt_link = f"https://www.youtube.com/watch?v={yt_code}"
                links.append(f"{title} : {yt_link}")
            else:
                video_link = f"https://apps-s3-jw-prod.utkarshapp.com/admin_v1/file_library/videos/enc_plain_mp4/{vid_id}/plain/720x1280.mp4"
                links.append(f"{title} : {video_link}")

def process_topic(subject_id: int, topic_id: int, batch_id: int, headers: dict):
    topic_links = []
    topic_name = f"Topic_{topic_id}"
    try:
        payload2 = {
            "course_id": str(subject_id),
            "parent_id": str(batch_id),
            "layer": "2",
            "page": "1",
            "revert_api": "1#0#0#1",
            "subject_id": str(topic_id),
            "tile_id": "0",
            "topic_id": str(topic_id),
            "type": "content"
        }
        cipher2 = AES.new(KEY, AES.MODE_CBC, IV)
        enc2 = base64.b64encode(cipher2.encrypt(pad(json.dumps(payload2).encode(), AES.block_size))).decode()
        resp2 = requests.post(TILES_URL, headers=headers, data={'tile_input': enc2, 'csrf_name': CSRF_TOKEN}, timeout=TIMEOUT)
        data2 = resp2.json().get('response', '')
        data2 = data2.replace('MDE2MTA4NjQxMDI3NDUxNQ==', '==').replace(':', '==')
        subtopics = json.loads(decrypt(data2)).get('data', {}).get('list', [])
        if subtopics:
            topic_title = subtopics[0].get('title')
            if topic_title:
                topic_name = topic_title
        for sub in subtopics:
            sid = sub['id']
            payload3 = {
                "course_id": str(subject_id),
                "parent_id": str(batch_id),
                "layer": "3",
                "page": "1",
                "revert_api": "1#0#0#1",
                "subject_id": str(topic_id),
                "tile_id": "0",
                "topic_id": str(sid),
                "type": "content"
            }
            enc3 = base64.b64encode(json.dumps(payload3, separators=(',', ':')).encode()).decode()
            resp3 = requests.post(
                LAYER2_URL,
                headers=headers,
                data={
                    'layer_two_input_data': enc3,
                    'content': 'content',
                    'csrf_name': CSRF_TOKEN
                },
                timeout=TIMEOUT
            )
            data3 = resp3.json().get('response', '')
            data3 = data3.replace('MDE2MTA4NjQxMDI3NDUxNQ==', '==').replace(':', '==')
            decoded = decrypt(data3)
            try:
                json_data = json.loads(decoded)
            except Exception:
                continue
            links = []
            process_layer3_videos(json_data, links)
            if links:
                topic_links.append(f"== {topic_name} ==")
                topic_links.extend(links)
    except Exception as e:
        print(colored(f"⚠️ Error in topic {topic_id}: {e}", "yellow"))
    return topic_links if topic_links else None

def process_single_subject(subject: dict, batch_id: int, headers: dict):
    subject_id = subject.get('id')
    subject_name = subject.get('title', 'Unknown')
    print(f"\n🔹 Subject '{subject_name}' (ID {subject_id})")
    payload = {
        "course_id": str(subject_id),
        "layer": "1",
        "page": "1",
        "parent_id": str(batch_id),
        "revert_api": "1#0#0#1",
        "tile_id": "0",
        "type": "content"
    }
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    enc = base64.b64encode(cipher.encrypt(pad(json.dumps(payload).encode(), AES.block_size))).decode()
    resp = requests.post(TILES_URL, headers=headers, data={'tile_input': enc, 'csrf_name': CSRF_TOKEN}, timeout=TIMEOUT)
    data = resp.json().get('response', '')
    data = data.replace('MDE2MTA4NjQxMDI3NDUxNQ==', '==').replace(':', '==')
    decrypted = decrypt(data)

    try:
        parsed = json.loads(decrypted)
        # Sometimes the structure may differ
        topics = parsed.get('data', [])
        if isinstance(topics, dict):
            topics = topics.get('list', [])
    except Exception as e:
        print(colored(f"❌ Failed to parse decrypted topics: {e}", "red"))
        return []

    result = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for i, t in enumerate(topics):
            topic_name = t.get('title', f"Topic_{t.get('id')}")
            topic_id = t['id']
            futures.append((i, topic_name, executor.submit(process_topic, subject_id, topic_id, batch_id, headers)))

        sorted_results = [None] * len(futures)
        for i, topic_name, fut in futures:
            topic_result = fut.result()
            if topic_result:
                sorted_results[i] = (topic_name, topic_result)

        for item in sorted_results:
            if item:
                name, blocks = item
                result.append(f"****************\nSubject: {name}\n****************")
                result.extend(blocks)

    return result

def main():
    headers = get_headers()
    batch_ids = ask_batch_ids()
    for bid in batch_ids:
        print(f"\n=== Batch {bid} ===")
        subjects = fetch_subjects(int(bid), headers)
        if not subjects:
            print(colored("❌ No subjects found!", "red"))
            continue

        batch_name_only = subjects[0].get('title', f"BATCH_{bid}") if subjects else f"BATCH_{bid}"
        sanitized_name = sanitize_filename(batch_name_only)
        pretty_batch_name = f"{bid}_{sanitized_name}"

        all_links = []

        for subj in subjects:
            subject_result = process_single_subject(subj, int(bid), headers)
            if subject_result:
                all_links.extend(subject_result)

        filename = f"{pretty_batch_name}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"UTKARSH Content for batch '{pretty_batch_name}' (ID: {bid})\n\n")
            f.write("\n".join(all_links))
        print(f"Saved content to {filename}")

        telegram_caption = (
            f"<b>APP NAME :</b> <code>UTKARSH</code>\n\n"
            f"<b>Batch ID :</b> <code>{bid}</code>\n"
            f"<b>Batch Name :</b> <code>{pretty_batch_name}</code>\n\n"
            "💟🙏"
        )
        sent = send_file_telegram(
            TELEGRAM_CHANNEL_ID,
            TELEGRAM_BOT_TOKEN,
            filename,
            telegram_caption
        )
        if sent:
            try:
                os.remove(filename)
                print(colored(f"🗑️ Deleted file {filename} after sending.", "cyan"))
            except Exception as ex:
                print(colored(f"⚠️ Could not delete {filename}: {ex}", "yellow"))

if __name__ == "__main__":
    main()
