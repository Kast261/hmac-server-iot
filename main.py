from flask import Flask, request, jsonify, make_response
import hmac
import hashlib
import json
import os

# Tuân thủ PEP 8: Mỗi import trên một dòng riêng biệt.

app = Flask(__name__)

# Đặt biến SECRET_KEY ngay khi khởi động
SECRET_KEY = os.getenv("SECRET_KEY", "day-la-khoa-bi-mat-cuc-manh-12345")


def log_request():
    """Ghi lại thông tin chi tiết của request đến."""
    print("=== NEW REQUEST ===")
    print("Method:", request.method)
    print("Path:", request.path)
    print("Headers:")
    for k, v in request.headers.items():
        print(f"  {k}: {v}")
    try:
        raw = request.get_data()
        print("Raw body bytes:", raw)
    except Exception as e:
        print("Không thể đọc body:", e)
    print("===================")


def add_cors(resp):
    """Thêm các tiêu đề CORS (Cross-Origin Resource Sharing) vào phản hồi."""
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Signature'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    return resp


@app.route('/')
def home():
    """Trang chủ đơn giản."""
    return "IoT Server đang chạy. Endpoint: /insecure_data và /secure_data", 200


@app.route('/insecure_data', methods=['POST', 'GET', 'OPTIONS'])
def handle_insecure_data():
    """Xử lý dữ liệu không cần xác thực HMAC."""
    log_request()
    if request.method == 'OPTIONS':
        # Phản hồi pre-flight request của CORS
        return add_cors(make_response('', 204))

    if request.method == 'GET':
        return add_cors(
            jsonify({
                'status': 'OK',
                'msg': 'GET on /insecure_data'
            })), 200

    try:
        # Sử dụng get_data() và json.loads() an toàn hơn
        payload_bytes = request.get_data()
        data = json.loads(payload_bytes.decode('utf-8'))

        print("-> Đã nhận dữ liệu KHÔNG BẢO MẬT:", data)
        return add_cors(jsonify({
            'status': 'Nhận thành công',
            'data': data
        })), 200
    except json.JSONDecodeError as e:
        print("Lỗi khi parse JSON cho /insecure_data:", e)
        return add_cors(
            jsonify({
                'status': 'Lỗi',
                'message': 'Dữ liệu không phải JSON hợp lệ'
            })), 400
    except Exception as e:
        print("Lỗi không xác định khi xử lý /insecure_data:", e)
        return add_cors(jsonify({'status': 'Lỗi', 'message': str(e)})), 500


@app.route('/secure_data', methods=['POST', 'GET', 'OPTIONS'])
def handle_secure_data():
    """Xử lý dữ liệu yêu cầu xác thực HMAC."""
    log_request()
    if request.method == 'OPTIONS':
        # Phản hồi pre-flight request của CORS
        return add_cors(make_response('', 204))

    if request.method == 'GET':
        return add_cors(jsonify({
            'status': 'OK',
            'msg': 'GET on /secure_data'
        })), 200

    received_sig = request.headers.get('X-Signature')
    if not received_sig:
        print("-> TỪ CHỐI (401): Thiếu tiêu đề X-Signature.")
        return add_cors(
            jsonify({
                'status': 'Lỗi',
                'message': 'Thiếu chữ ký HMAC'
            })), 401

    payload_bytes = request.get_data()

    # Tính toán HMAC
    computed_sig = hmac.new(SECRET_KEY.encode('utf-8'), payload_bytes,
                            hashlib.sha256).hexdigest()

    # So sánh chữ ký bằng hmac.compare_digest để chống tấn công timing
    if not hmac.compare_digest(received_sig, computed_sig):
        print("-> TỪ CHỐI (403): Chữ ký KHÔNG HỢP LỆ.")
        print(f"   Nhận được: {received_sig}")
        print(f"   Tính toán: {computed_sig}")
        return add_cors(
            jsonify({
                'status': 'Lỗi',
                'message': 'Chữ ký không hợp lệ'
            })), 403

    try:
        # Nếu chữ ký hợp lệ, parse JSON
        data = json.loads(payload_bytes.decode('utf-8'))
        print(f"-> ĐÃ XÁC MINH (200): Nhận dữ liệu hợp lệ: {data}")
        return add_cors(jsonify({'status': 'Đã xác minh', 'data': data})), 200
    except json.JSONDecodeError as e:
        print(f"Lỗi: Không thể parse JSON sau khi xác minh chữ ký: {e}")
        return add_cors(
            jsonify({
                'status': 'Lỗi',
                'message': 'Dữ liệu không phải JSON hợp lệ'
            })), 400
    except Exception as e:
        print(f"Lỗi không xác định: {e}")
        return add_cors(jsonify({'status': 'Lỗi', 'message': str(e)})), 500


if __name__ == '__main__':
    # Flask mặc định đã tìm thấy cổng thích hợp trên Replit,
    # nhưng bạn nên giữ cấu hình cổng 5000 nếu muốn.
    # Tuy nhiên, hãy thêm file .replit để đảm bảo Replit nhận ra cổng này.
    app.run(host='0.0.0.0',port=8000, debug=True)
