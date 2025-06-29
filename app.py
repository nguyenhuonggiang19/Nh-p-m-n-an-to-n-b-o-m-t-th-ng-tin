from datetime import datetime, timedelta
import os
import json
import hashlib
from base64 import b64encode
from collections import Counter
from flask import session
from flask import send_from_directory
from flask import Flask, request, redirect, render_template
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
app.secret_key = "cvscan-secret-123"

# Thư mục & đường dẫn
THU_MUC_TAI = "uploads"
THU_MUC_KHOA = "keys"
THU_MUC_MA_HOA = "encrypted"
FILE_LOG = "log.json"
FILE_DSCHAN = "dsIPChan.json"

# Tạo thư mục nếu chưa có
os.makedirs(THU_MUC_TAI, exist_ok=True)
os.makedirs(THU_MUC_KHOA, exist_ok=True)
os.makedirs(THU_MUC_MA_HOA, exist_ok=True)

# Hàm: Tạo mới hoặc tải khóa RSA từ file
# Trả về: private_key, public_key
def taiHoacTaoKhoa():
    priv_path = os.path.join(THU_MUC_KHOA, "private.pem")
    pub_path = os.path.join(THU_MUC_KHOA, "public.pem")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = private_key.public_key()
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        with open(pub_path, "wb") as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_key, public_key

# Hàm: Tính hàm băm SHA-512 từ dữ liệu
# Trả về chuỗi hex
def tinhHashSHA512(noiDung):
    return hashlib.sha512(noiDung).hexdigest()

# Hàm: Mã hóa dữ liệu bằng AES-CBC
# Trả về: key AES, IV, dữ liệu đã mã hóa
def maHoaAES_CBC(data):
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return key, iv, encrypted

# Hàm: Ký chuỗi metadata bằng khóa RSA (SHA-512)
# Trả về: chữ ký dạng byte
def kySo(metadata_str, private_key):
    return private_key.sign(
        metadata_str.encode(),
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA512()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA512()
    )

# Hàm: Kiểm tra IP có nguy hiểm không dựa trên các tiêu chí
# Trả về True nếu nghi ngờ, False nếu hợp lệ
def laIpNguyHiem(ip, hoTen, email, tenFile, kichThuocFile, danhSachLog):
    now = datetime.now()
    dem = 0
    for dong in danhSachLog:
        if dong['ip'] == ip:
            thoiGianGui = datetime.strptime(dong['time'], "%Y-%m-%d %H:%M:%S")
            if now - thoiGianGui <= timedelta(minutes=5):
                dem += 1
    if dem >= 3:
        return True
    if not tenFile.lower().endswith(".pdf") or len(tenFile) < 5 or len(tenFile) > 100:
        return True
    if kichThuocFile < 10000 or kichThuocFile > 5 * 1024 * 1024:
        return True
    if "@" not in email or "." not in email or len(email) < 5:
        return True
    if len(hoTen.strip().split()) < 2:
        return True
    if os.path.exists(FILE_DSCHAN):
        with open(FILE_DSCHAN, "r", encoding="utf-8") as f:
            if ip in json.load(f):
                return True
    tenFileLower = tenFile.lower()
    if any(x in tenFileLower for x in ['<script>', '.exe', '.bat', '.sh', '.js']):
        return True
    emails_tu_ip = {dong['email'] for dong in danhSachLog if dong['ip'] == ip}
    if len(emails_tu_ip) >= 3:
        return True
    if any(ip.startswith(dau) for dau in ["45.", "185.", "139."]):
        return True
    return False

# Route: Trang chủ và xử lý khi người dùng gửi CV
# @app.route("/", methods=["GET", "POST"])
# def xuLy():
#     if request.method == "GET":
#         return render_template("giaodien.html")

#     hoTen = request.form["name"]
#     email = request.form["email"]
#     file = request.files["cvfile"]
#     ip = request.remote_addr
#     filename = file.filename
#     filepath = os.path.join(THU_MUC_TAI, filename)
#     file.save(filepath)
#     fileSize = os.path.getsize(filepath)
#     nowStr = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#     danhSachLog = []
#     if os.path.exists(FILE_LOG):
#         with open(FILE_LOG, "r", encoding="utf-8") as f:
#             danhSachLog = json.load(f)

#     if laIpNguyHiem(ip, hoTen, email, filename, fileSize, danhSachLog):
#         return render_template("giaodien.html", result={
#             "ip": ip,
#             "ip_status": "❌ IP bị từ chối",
#             "filename": filename,
#             "file_status": "Bị chặn do nghi ngờ",
#             "hash": "---",
#             "sign_status": "Không thực hiện",
#             "encrypt_status": "Không thực hiện",
#             "log_status": "Không ghi log"
#         })

#     with open(filepath, "rb") as f:
#         noiDungFile = f.read()
#     khoaAES, iv, ciphertext = maHoaAES_CBC(noiDungFile)
#     hash_du_lieu = tinhHashSHA512(iv + ciphertext)
#     private_key, public_key = taiHoacTaoKhoa()
#     metadata = f"{filename}|{nowStr}|{ip}"
#     chuKy = kySo(metadata, private_key)
#     fileEncPath = os.path.join(THU_MUC_MA_HOA, f"enc_{filename}")
#     with open(fileEncPath, "wb") as f:
#         f.write(iv + ciphertext)

#     danhSachLog.append({
#         "ip": ip, "name": hoTen, "email": email, "file": filename,
#         "time": nowStr, "hash": hash_du_lieu,
#         "chuky": b64encode(chuKy).decode()
#     })
#     with open(FILE_LOG, "w", encoding="utf-8") as f:
#         json.dump(danhSachLog, f, indent=2, ensure_ascii=False)

#     return render_template("giaodien.html", result={
#         "ip": ip,
#         "ip_status": "✅ Hợp lệ",
#         "filename": filename,
#         "file_status": "Hợp lệ & đã xử lý",
#         "hash": hash_du_lieu,
#         "sign_status": "✅ Đã ký SHA-512",
#         "encrypt_status": "✅ AES thành công",
#         "log_status": "✅ Ghi log"
#     })

@app.route("/", methods=["GET", "POST"])
def xuLy():
    if request.method == "GET":
        return render_template("giaodien.html")

    hoTen = request.form["name"]
    email = request.form["email"]
    file = request.files["cvfile"]
    ip = request.remote_addr
    filename = file.filename
    filepath = os.path.join(THU_MUC_TAI, filename)
    file.save(filepath)
    fileSize = os.path.getsize(filepath)
    nowStr = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Kiểm tra định dạng file
    if not filename.lower().endswith(".pdf"):
        return render_template("giaodien.html", result={
            "ip": ip,
            "ip_status": "❌ IP bị từ chối",
            "filename": filename,
            "file_status": "Định dạng file không hợp lệ",
            "hash": "---",
            "sign_status": "Không thực hiện",
            "encrypt_status": "Không thực hiện",
            "log_status": "Không ghi log"
    })

    # Đọc 4 byte đầu để chắc là PDF (PDF bắt đầu bằng "%PDF")
    with open(filepath, "rb") as f:
        if not f.read(4).startswith(b'%PDF'):
            return render_template("giaodien.html", result={
                "ip": ip,
                 "ip_status": "❌ IP bị từ chối",
                "filename": filename,
                "file_status": "Không phải file PDF thật",
                "hash": "---",
                "sign_status": "Không thực hiện",
                "encrypt_status": "Không thực hiện",
                "log_status": "Không ghi log"
            })

    # Load danh sách IP bị chặn
    danhSachChan = []
    if os.path.exists(FILE_DSCHAN):
        with open(FILE_DSCHAN, "r", encoding="utf-8") as f:
            danhSachChan = json.load(f)
    if ip in danhSachChan:
        return render_template("giaodien.html", result={
            "ip": ip,
            "ip_status": "❌ IP đã bị chặn",
            "filename": filename,
            "file_status": "Từ chối vĩnh viễn",
            "hash": "---",
            "sign_status": "Không thực hiện",
            "encrypt_status": "Không thực hiện",
            "log_status": "Không ghi log"
        })

    # Load lịch sử log
    danhSachLog = []
    if os.path.exists(FILE_LOG):
        with open(FILE_LOG, "r", encoding="utf-8") as f:
            danhSachLog = json.load(f)

    # Kiểm tra spam: gửi trùng file từ IP trong vòng 5 phút
    viPham = [
        log for log in danhSachLog
        if log["ip"] == ip and log["file"] == filename and
        (datetime.now() - datetime.strptime(log["time"], "%Y-%m-%d %H:%M:%S")).total_seconds() < 300
    ]
    if len(viPham) >= 3:
        # Ghi log từ chối
        logTC = []
        if os.path.exists("log_tu_choi.json"):
            with open("log_tu_choi.json", "r", encoding="utf-8") as f:
                logTC = json.load(f)
        logTC.append({
            "ip": ip, "name": hoTen, "email": email, "file": filename,
            "time": nowStr, "ly_do": "Spam file trùng tên > 3 lần trong 5 phút"
        })
        with open("log_tu_choi.json", "w", encoding="utf-8") as f:
            json.dump(logTC, f, indent=2, ensure_ascii=False)

        # Thêm vào danh sách chặn
        if ip not in danhSachChan:
            danhSachChan.append(ip)
            with open(FILE_DSCHAN, "w", encoding="utf-8") as f:
                json.dump(danhSachChan, f, indent=2, ensure_ascii=False)

        return render_template("giaodien.html", result={
            "ip": ip,
            "ip_status": "❌ IP bị từ chối do spam",
            "filename": filename,
            "file_status": "Bị chặn do nghi ngờ",
            "hash": "---",
            "sign_status": "Không thực hiện",
            "encrypt_status": "Không thực hiện",
            "log_status": "Không ghi log"
        })

    # Xử lý mã hóa & ký số
    with open(filepath, "rb") as f:
        noiDungFile = f.read()
        khoaAES, iv, ciphertext = maHoaAES_CBC(noiDungFile)
        hash_du_lieu = tinhHashSHA512(iv + ciphertext)
        private_key, public_key = taiHoacTaoKhoa()
        metadata = f"{filename}|{nowStr}|{ip}"
        chuKy = kySo(metadata, private_key)

    fileEncPath = os.path.join("tep_ma_hoa", f"enc_{filename}")
    with open(fileEncPath, "wb") as f:
        f.write(iv + ciphertext)

    # Ghi log gửi thành công
    danhSachLog.append({
        "ip": ip, "name": hoTen, "email": email, "file": filename,
        "time": nowStr, "hash": hash_du_lieu,
        "chuky": b64encode(chuKy).decode()
    })
    with open(FILE_LOG, "w", encoding="utf-8") as f:
        json.dump(danhSachLog, f, indent=2, ensure_ascii=False)

    return render_template("giaodien.html", result={
        "ip": ip,
        "ip_status": "✅ Hợp lệ",
        "filename": filename,
        "file_status": "Hợp lệ & đã xử lý",
        "hash": hash_du_lieu,
        "sign_status": "✅ Đã ký SHA-512",
        "encrypt_status": "✅ AES thành công",
        "log_status": "✅ Ghi log"
    })

# Route: Đăng nhập admin bằng username/password từ file
@app.route('/admin-login', methods=['GET', 'POST'])
def dangNhapAdmin():
    try:
        if request.is_json:
            data = request.get_json()
            username = data.get('username', '')
            password = data.get('password', '')
        else:
            username = request.form['username']
            password = request.form['password']
        with open('admin.txt', 'r', encoding='utf-8') as f:
            line = f.readline().strip()
            stored_username, stored_password = line.split(' ', 1)

        if username == stored_username and password == stored_password:
            session['admin_logged_in'] = True
            return redirect('/admin')

        else:
            return render_template('admin-login.html', error='Sai tài khoản hoặc mật khẩu.')
    except Exception as e:
        return render_template('admin-login.html', error='Lỗi khi kiểm tra tài khoản.')

# Route: Giao diện chính dành cho admin xem danh sách CV và thống kê IP
@app.route("/admin")
def trangQuanLy():
    if not session.get("admin_logged_in"):
        return redirect("/admin-login")
    try:
        if not os.path.exists(FILE_LOG):
            danhSachCV = []
            thongKeIP = {}
        else:
            with open(FILE_LOG, "r", encoding="utf-8") as f:
                danhSachCV = json.load(f)
                thongKeIP = dict(Counter(item['ip'] for item in danhSachCV))    
        return render_template("admin.html", danhSachCV=danhSachCV, thongKeIP=thongKeIP)
    except Exception as e:
        return f"Lỗi khi tải trang admin: {e}"

# Route: Phục vụ xử lý upload từ client (POST tới /upload)
@app.route("/upload", methods=["POST"])
def uploadCV():
    return xuLy()  # gọi lại hàm xử lý chính

# Route: Trang chi tiết CV theo index (admin xem chi tiết từng CV)
@app.route('/chi-tiet/<int:index>')
def chiTietCV(index):
    if not session.get("admin_logged_in"):
        return redirect("/admin-login")
    if not os.path.exists(FILE_LOG):
        return "Không có dữ liệu"

    with open(FILE_LOG, "r", encoding="utf-8") as f:
        danhSach = json.load(f)

    if index < 0 or index >= len(danhSach):
        return "CV không tồn tại"

    cv = danhSach[index]
    file_path = os.path.join(THU_MUC_TAI, cv["file"])

    if not os.path.exists(file_path):
        return "File đã bị xóa hoặc không tồn tại"

    return render_template("chiTiet.html", cv=cv)

# Route: Phục vụ file PDF cho phép mở trực tiếp (không tải về)
@app.route('/uploads/<path:filename>')
def taiFile(filename):
    return send_from_directory(THU_MUC_TAI, filename , mimetype='application/pdf', as_attachment=False)

# Route: Admin gửi yêu cầu chặn 1 IP cụ thể, xóa file liên quan, cập nhật log
@app.route("/chan-ip", methods=["POST"])
def chanIp():
    ip = request.form.get("ip")
    if not session.get("admin_logged_in"):
        return redirect("/admin-login")
    if not ip:
        return "Không có IP", 400

    danhSachChan = []
    if os.path.exists(FILE_DSCHAN):
        with open(FILE_DSCHAN, "r", encoding="utf-8") as f:
            danhSachChan = json.load(f)

    if ip not in danhSachChan:
        danhSachChan.append(ip)
        with open(FILE_DSCHAN, "w", encoding="utf-8") as f:
            json.dump(danhSachChan, f, indent=2, ensure_ascii=False)

    # Xóa toàn bộ file từ IP này (chỉ xóa file, giữ lại log nếu bạn muốn theo dõi)
    if os.path.exists(FILE_LOG):
        with open(FILE_LOG, "r", encoding="utf-8") as f:
            log = json.load(f)
        # Lọc lại log nếu muốn, hoặc không cần
        for item in log:
            if item['ip'] == ip:
                path = os.path.join(THU_MUC_TAI, item['file'])
                if os.path.exists(path):
                    os.remove(path)

        # Cập nhật lại log nếu muốn xóa các mục liên quan
        log = [item for item in log if item['ip'] != ip]
        with open(FILE_LOG, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2, ensure_ascii=False)

    mahoa_path = os.path.join(THU_MUC_MA_HOA, f"enc_{item['file']}")
    if os.path.exists(mahoa_path):
        os.remove(mahoa_path)

    return redirect("/admin")

# Route: Đăng xuất admin, xóa session và quay về giao diện chính
@app.route("/logout")
def dangXuat():
    session.pop("admin_logged_in", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
