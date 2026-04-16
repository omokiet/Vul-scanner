import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

def fetch_banner(ip, port, timeout=2.0):
    """
    Kết nối vào một cổng để lấy nội dung Banner trả về (version ứng dụng, OS)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Nếu cổng Web HTTP, ta gửi một HTTP Request để dụ server trả về Header (chứa Server banner)
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in [443, 8443]:
                return "Bảo mật SSL/TLS (Xem thông tin ở Tab khác)"
                
            banner_bytes = s.recv(1024)
            if banner_bytes:
                text = banner_bytes.decode('utf-8', errors='ignore').strip()
                
                # Phân tích Server HTTP
                if port in [80, 8080]:
                    for line in text.split('\n'):
                        if line.lower().startswith('server:'):
                            return line.split(':', 1)[1].strip()
                    # Trả về dòng đầu tiên nếu không có server header (VD: HTTP/1.1 200 OK)
                    return text.split('\n')[0].strip()
                    
                # Xử lý các protocol khác như SSH, FTP, SMTP (lấy dòng đầu tiên để lấy banner)
                return text.split('\n')[0].strip()[:100] 
                
    except Exception:
        pass
    
    return "Không nhận diện được Service/Banner (Có thể do thiết lập ẩn version)"


def analyze_banners(ip, open_ports):
    """
    Tiến hành Banner Grabbing theo luồng và tạo URL tra cứu CVE từ National Vulnerability Database (NVD)
    """
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        # submit tasks
        futures = {executor.submit(fetch_banner, ip, port): port for port in open_ports}
        for future in futures:
            port = futures[future]
            banner = future.result()
            
            # Sinh ra URL tìm kiếm lỗ hổng NVD
            nvd_link = ""
            if banner and banner != "Bảo mật SSL/TLS (Xem thông tin ở Tab khác)" and not banner.startswith("Không nhận diện"):
                # Gửi chuỗi URL-encoded để search trên trang của NIST.
                query = urllib.parse.quote(banner)
                nvd_link = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={query}&search_type=all"
            
            results.append({
                "port": port,
                "banner": banner,
                "nvd_url": nvd_link
            })
            
    # Sắp xếp kết quả cho khoa học theo cổng
    return sorted(results, key=lambda x: x["port"])
