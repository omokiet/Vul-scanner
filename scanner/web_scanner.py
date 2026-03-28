import requests
import random
import string
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("WebScanner")

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'X-XSS-Protection'
]

# Đây là thư mục (wordlist) Fuzzer sẽ dò tìm. 
# Trong Tool thực tế, wordlist lên tới hàng vạn từ.
COMMON_DIRECTORIES = [
    'admin', 'login', 'config.php', '.env', '.git/', 
    'backup', 'db.sql', 'phpmyadmin', 'test', 'dashboard',
    'robots.txt', 'wp-admin', 'api'
]

def check_security_headers(url):
    """
    Lấy Response Headers và so sánh với danh sách an toàn.
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    logger.info(f"Bắt đầu phân tích HTTP Headers cho: {url}")
    try:
        # Cho timeout 5s, bỏ qua chứng chỉ SSL lỗi nếu có (verify=False mặc định nên tắt để tránh lỗi kết nối môi trường test)
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        
        missing_headers = []
        present_headers = []
        
        for header in SECURITY_HEADERS:
            if header in headers:
                present_headers.append(header)
            else:
                missing_headers.append(header)
                
        return {
            "status_code": response.status_code,
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "url": url,
            "server": headers.get("Server", "Unknown/Hidden")
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def check_single_directory(base_url, directory, is_catch_all=False, baseline_length=0):
    """
    Hàm fuzz 1 endpoint. Tích hợp xử lý Soft 404.
    """
    url = f"{base_url}/{directory}"
    try:
        # Gửi Request lên thư mục. Mốc chuẩn là 200, 301, 302, 401, 403 đều được xem là có tồn tại thư mục
        response = requests.get(url, timeout=3, allow_redirects=False, verify=False)
        if response.status_code in [200, 301, 302, 401, 403]:
            # Xử lý báo cáo ảo (Soft 404 / Catch-all Router)
            if response.status_code == 200 and is_catch_all:
                # Nếu kích thước chênh lệch so với trang báo lỗi giả dưới 50 bytes -> Thực chất là file ảo / 404
                if abs(len(response.text) - baseline_length) < 50:
                    return directory, "Báo cáo ảo (Soft 404)"
            return directory, response.status_code
        return directory, None
    except Exception:
        return directory, None


def enumerate_directories(target_url, max_threads=10):
    """
    Thực hiện Multi-threading Directory Fuzzing.
    """
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
        
    target_url = target_url.rstrip('/')
    found_dirs = []
    
    # [Kiểm định Baseline] Thử gửi request vào một url ngẫu nhiên chắc chắn không tồn tại
    random_path = '/' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
    is_catch_all = False
    baseline_length = 0
    try:
        baseline_resp = requests.get(f"{target_url}{random_path}", timeout=5, verify=False)
        if baseline_resp.status_code == 200:
            is_catch_all = True
            baseline_length = len(baseline_resp.text)
            logger.warning(f"Phát hiện Catch-All Route! Baseline ảo tại mốc {baseline_length} bytes.")
    except Exception:
        pass
    
    logger.info(f"Mở {max_threads} luồng nhồi tải Fuzzing các thư mục...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_single_directory, target_url, dir_name, is_catch_all, baseline_length) for dir_name in COMMON_DIRECTORIES]
        
        for future in futures:
            dir_name, status = future.result()
            if status is not None and status != "Báo cáo ảo (Soft 404)":
                logger.warning(f"[+] Lộ tệp tin thực tế: /{dir_name} ({status})")
                found_dirs.append({"path": f"/{dir_name}", "status": status})
            elif status == "Báo cáo ảo (Soft 404)":
                pass
                
    logger.info(f"Tìm thấy tổng cộng {len(found_dirs)} tài nguyên bị lộ lọt.")
    return found_dirs
