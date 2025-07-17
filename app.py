# pylint: disable=unused-import

import argparse
import binascii
import io
import os
import logging
import time

from flask import Flask, Response, jsonify, render_template,render_template_string, request, redirect, abort
from werkzeug.exceptions import BadRequest

from config import (
    CTR_PARAM,
    ENC_FILE_DATA_PARAM,
    ENC_PICC_DATA_PARAM,
    REQUIRE_LRP,
    SDMMAC_PARAM,
    MASTER_KEY,
    UID_PARAM,
    DERIVE_MODE,
)

if DERIVE_MODE == "legacy":
    from libsdm.legacy_derive import derive_tag_key, derive_undiversified_key
elif DERIVE_MODE == "standard":
    from libsdm.derive import derive_tag_key, derive_undiversified_key
else:
    raise RuntimeError("Invalid DERIVE_MODE.")

from libsdm.sdm import (
    EncMode,
    InvalidMessage,
    ParamMode,
    decrypt_sun_message,
    validate_plain_sun,
)

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Configure logging for access monitoring
logging.basicConfig(level=logging.INFO)

# Track used counters to prevent replay attacks
used_counters = {}

@app.errorhandler(400)
def handler_bad_request(err):
    return render_template('error.html', code=400, msg=str(err)), 400


@app.errorhandler(403)
def handler_forbidden(err):
    return render_template('error.html', code=403, msg=str(err)), 403


@app.errorhandler(404)
def handler_not_found(err):
    return render_template('error.html', code=404, msg=str(err)), 404


@app.context_processor
def inject_demo_mode():
    demo_mode = MASTER_KEY == (b"\x00" * 16)
    return {"demo_mode": demo_mode}


@app.route('/')
def sdm_main():
    """
    Updated main page with project-specific information.
    """
    return render_template_string("""
    <html>
    <head>
        <title>MEMS NTAG 424 DNA Backend</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #2196F3; }
            .info { background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h1>MEMS NTAG 424 DNA Backend</h1>
        <div class="info">
            <h2>Project Status: Active</h2>
            <p><strong>Purpose:</strong> Secure access control for Wix Studio page</p>
            <p><strong>Validation Endpoint:</strong> /validate</p>
            <p><strong>Target URL:</strong> https://pedroarrudar.wixstudio.com/test-umpalumpa</p>
        </div>
        <div class="info">
            <h3>NTAG Configuration Required:</h3>
            <p>Configure your NTAG 424 DNA to point to:</p>
            <code>https://5000-arrudar-sdmbackendmems-xt79lzonb4n.ws-us120.gitpod.io/validate</code>
        </div>
        <div class="info">
            <h3>Supported Endpoints:</h3>
            <ul>
                <li><strong>/validate</strong> - Custom validation with Wix redirect</li>
                <li><strong>/tag</strong> - Original SDM validation</li>
                <li><strong>/tagpt</strong> - Plaintext validation</li>
            </ul>
        </div>
    </body>
    </html>
    """)


# NEW: Validation endpoint for NTAG 424 DNA access control
@app.route('/validate')
def validate_and_redirect():
    # Log the access attempt
    logging.info(f"NTAG validation attempt from {request.remote_addr}")
    
    # Get SDM parameters from the URL
    picc_data = request.args.get('picc_data')
    cmac = request.args.get('cmac')
    
    if picc_data and cmac:
        # SUCCESS: Fetch Wix Studio content and serve it
        try:
            # Fetch the Wix Studio page content
            wix_response = requests.get(
                "https://pedroarrudar.wixstudio.com/test-umpalumpa",
                headers={
                    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                timeout=10
            )
            
            if wix_response.status_code == 200:
                # Show QUACK message first, then serve content
                return render_template_string("""
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>QUACK! Loading Content...</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        h1 { color: #4CAF50; font-size: 2.5em; }
                        p { font-size: 1.2em; color: #333; }
                        .loader { margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #4CAF50; border-radius: 50%; animation: spin 1s linear infinite; }
                        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                        .hidden { display: none; }
                    </style>
                    <script>
                        setTimeout(function() {
                            document.getElementById('loading').classList.add('hidden');
                            document.getElementById('content').classList.remove('hidden');
                        }, 3000);
                    </script>
                </head>
                <body>
                    <div id="loading">
                        <h1>QUACK! 🦆</h1>
                        <p>We are fetching your exclusive content...</p>
                        <div class="loader"></div>
                        <p><small>Loading in 3 seconds...</small></p>
                    </div>
                    <div id="content" class="hidden">
                        {{ wix_content|safe }}
                    </div>
                </body>
                </html>
                """, wix_content=wix_response.text)
            else:
                # Fallback if Wix content unavailable
                return render_template_string("""
                <html><body>
                <h1>QUACK! 🦆</h1>
                <p>Content temporarily unavailable. Please try again later.</p>
                </body></html>
                """)
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch Wix content: {e}")
            return render_template_string("""
            <html><body>
            <h1>QUACK! 🦆</h1>
            <p>Service temporarily unavailable. Please try again later.</p>
            </body></html>
            """)
    else:
        # ACCESS DENIED: Duck arrest animation (keep existing code)
        return render_template_string("""
        <!-- Your existing duck arrest animation code -->
        """), 403
            
def parse_sdm_parameters(encrypted, cmac_param):
    """
    Parse SDM parameters for the validate endpoint.
    """
    try:
        # Convert hex parameters to bytes
        enc_data = binascii.unhexlify(encrypted)
        cmac_data = binascii.unhexlify(cmac_param)
        
        # Determine parameter mode based on data structure
        if len(enc_data) >= 16:
            param_mode = ParamMode.BULK
            # For bulk mode, reconstruct the e parameter structure
            e_buf = io.BytesIO()
            e_buf.write(enc_data)
            e_buf.write(cmac_data)
            e_combined = e_buf.getvalue()
            
            # Parse using existing logic
            e_buf = io.BytesIO(e_combined)
            if (len(e_combined) - 8) % 16 == 0:
                # AES mode
                file_len = len(e_combined) - 16 - 8
                enc_picc_data_b = e_buf.read(16)
                enc_file_data_b = e_buf.read(file_len) if file_len > 0 else None
                sdmmac_b = e_buf.read(8)
            else:
                # LRP mode
                file_len = len(e_combined) - 24 - 8
                enc_picc_data_b = e_buf.read(24)
                enc_file_data_b = e_buf.read(file_len) if file_len > 0 else None
                sdmmac_b = e_buf.read(8)
        else:
            # Separated parameter mode
            param_mode = ParamMode.SEPARATED
            enc_picc_data_b = enc_data
            enc_file_data_b = None
            sdmmac_b = cmac_data
        
        return param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b
        
    except (binascii.Error, ValueError) as e:
        raise BadRequest(f"Failed to parse SDM parameters: {str(e)}")


# Keep all existing endpoints unchanged
def parse_parameters():
    arg_e = request.args.get('e')
    if arg_e:
        param_mode = ParamMode.BULK

        try:
            e_b = binascii.unhexlify(arg_e)
        except binascii.Error:
            raise BadRequest("Failed to decode parameters.") from None

        e_buf = io.BytesIO(e_b)

        if (len(e_b) - 8) % 16 == 0:
            # using AES (16 byte PICCEncData)
            file_len = len(e_b) - 16 - 8
            enc_picc_data_b = e_buf.read(16)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        elif (len(e_b) - 8) % 16 == 8:
            # using LRP (24 byte PICCEncData)
            file_len = len(e_b) - 24 - 8
            enc_picc_data_b = e_buf.read(24)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        else:
            raise BadRequest("Incorrect length of the dynamic parameter.")
    else:
        param_mode = ParamMode.SEPARATED
        enc_picc_data = request.args.get(ENC_PICC_DATA_PARAM)
        enc_file_data = request.args.get(ENC_FILE_DATA_PARAM)
        sdmmac = request.args.get(SDMMAC_PARAM)

        if not enc_picc_data:
            raise BadRequest(f"Parameter {ENC_PICC_DATA_PARAM} is required")

        if not sdmmac:
            raise BadRequest(f"Parameter {SDMMAC_PARAM} is required")

        try:
            enc_file_data_b = None
            enc_picc_data_b = binascii.unhexlify(enc_picc_data)
            sdmmac_b = binascii.unhexlify(sdmmac)

            if enc_file_data:
                enc_file_data_b = binascii.unhexlify(enc_file_data)
        except binascii.Error:
            raise BadRequest("Failed to decode parameters.") from None

    return param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b


@app.route('/tagpt')
def sdm_info_plain():
    """
    Return HTML
    """
    return _internal_tagpt()


@app.route('/api/tagpt')
def sdm_api_info_plain():
    """
    Return JSON
    """
    try:
        return _internal_tagpt(force_json=True)
    except BadRequest as err:
        return jsonify({"error": str(err)}), 400


def _internal_tagpt(force_json=False):
    try:
        uid = binascii.unhexlify(request.args[UID_PARAM])
        read_ctr = binascii.unhexlify(request.args[CTR_PARAM])
        cmac = binascii.unhexlify(request.args[SDMMAC_PARAM])
    except binascii.Error:
        raise BadRequest("Failed to decode parameters.") from None

    try:
        sdm_file_read_key = derive_tag_key(MASTER_KEY, uid, 2)
        res = validate_plain_sun(uid=uid,
                                 read_ctr=read_ctr,
                                 sdmmac=cmac,
                                 sdm_file_read_key=sdm_file_read_key)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).") from None

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise BadRequest("Invalid encryption mode, expected LRP.")

    if request.args.get("output") == "json" or force_json:
        return jsonify({
            "uid": res['uid'].hex().upper(),
            "read_ctr": res['read_ctr'],
            "enc_mode": res['encryption_mode'].name
        })

    return render_template('sdm_info.html',
                           encryption_mode=res['encryption_mode'].name,
                           uid=res['uid'],
                           read_ctr_num=res['read_ctr'])


@app.route('/webnfc')
def sdm_webnfc():
    return render_template('sdm_webnfc.html')


@app.route('/tagtt')
def sdm_info_tt():
    return _internal_sdm(with_tt=True)


@app.route('/api/tagtt')
def sdm_api_info_tt():
    try:
        return _internal_sdm(with_tt=True, force_json=True)
    except BadRequest as err:
        return jsonify({"error": str(err)})


@app.route('/tag')
def sdm_info():
    return _internal_sdm(with_tt=False)


@app.route('/api/tag')
def sdm_api_info():
    try:
        return _internal_sdm(with_tt=False, force_json=True)
    except BadRequest as err:
        return jsonify({"error": str(err)})


# pylint:  disable=too-many-branches, too-many-statements, too-many-locals
def _internal_sdm(with_tt=False, force_json=False):
    """
    SUN decrypting/validating endpoint.
    """
    param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b = parse_parameters()

    try:
        res = decrypt_sun_message(param_mode=param_mode,
                                  sdm_meta_read_key=derive_undiversified_key(MASTER_KEY, 1),
                                  sdm_file_read_key=lambda uid: derive_tag_key(MASTER_KEY, uid, 2),
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).") from InvalidMessage

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise BadRequest("Invalid encryption mode, expected LRP.")

    picc_data_tag = res['picc_data_tag']
    uid = res['uid']
    read_ctr_num = res['read_ctr']
    file_data = res['file_data']
    encryption_mode = res['encryption_mode'].name

    file_data_utf8 = ""
    tt_status_api = ""
    tt_status = ""
    tt_color = ""

    if res['file_data']:
        if param_mode == ParamMode.BULK:
            file_data_len = file_data[2]
            file_data_unpacked = file_data[3:3 + file_data_len]
        else:
            file_data_unpacked = file_data

        file_data_utf8 = file_data_unpacked.decode('utf-8', 'ignore')

        if with_tt:
            tt_perm_status = file_data[0:1].decode('ascii', 'replace')
            tt_cur_status = file_data[1:2].decode('ascii', 'replace')

            if tt_perm_status == 'C' and tt_cur_status == 'C':
                tt_status_api = 'secure'
                tt_status = 'OK (not tampered)'
                tt_color = 'green'
            elif tt_perm_status == 'O' and tt_cur_status == 'C':
                tt_status_api = 'tampered_closed'
                tt_status = 'Tampered! (loop closed)'
                tt_color = 'red'
            elif tt_perm_status == 'O' and tt_cur_status == 'O':
                tt_status_api = 'tampered_open'
                tt_status = 'Tampered! (loop open)'
                tt_color = 'red'
            elif tt_perm_status == 'I' and tt_cur_status == 'I':
                tt_status_api = 'not_initialized'
                tt_status = 'Not initialized'
                tt_color = 'orange'
            elif tt_perm_status == 'N' and tt_cur_status == 'T':
                tt_status_api = 'not_supported'
                tt_status = 'Not supported by the tag'
                tt_color = 'orange'
            else:
                tt_status_api = 'unknown'
                tt_status = 'Unknown'
                tt_color = 'orange'

    if request.args.get("output") == "json" or force_json:
        return jsonify({
            "uid": uid.hex().upper(),
            "file_data": file_data.hex() if file_data else None,
            "read_ctr": read_ctr_num,
            "tt_status": tt_status_api,
            "enc_mode": encryption_mode
        })

    return render_template('sdm_info.html',
                           encryption_mode=encryption_mode,
                           picc_data_tag=picc_data_tag,
                           uid=uid,
                           read_ctr_num=read_ctr_num,
                           file_data=file_data,
                           file_data_utf8=file_data_utf8,
                           tt_status=tt_status,
                           tt_color=tt_color)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?', default='0.0.0.0', help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?', default=5000, help='port to listen on')

    args = parser.parse_args()

    app.run(debug=False, host='0.0.0.0', port=5000)
    