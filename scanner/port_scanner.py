import socket
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("PortScanner")

def clean_target_domain(target):
    """Lọc bỏ http:// hoặc ký tự thừa để lấy domain chuẩn cho socket"""
    target = str(target).strip()
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).hostname
    return target.split('/')[0]

def scan_single_port(ip, port, timeout=1.0):
    """
    Kết nối socket TCP tới 1 cổng cụ thể trên địa chỉ IP.
    Trả về (port, is_open)
    """
    try:
        # AF_INET for IPv4, SOCK_STREAM for TCP connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port, True
            else:
                return port, False
    except Exception:
        return port, False

def scan_ports(target, ports, max_threads=50):
    """
    Quét danh sách (list) các cổng bằng đa luồng (multi-threading).
    """
    clean_domain = clean_target_domain(target)
    if not clean_domain:
        logger.error("Đầu vào rỗng hoặc không hợp lệ.")
        return {"error": "Domain/IP không hợp lệ."}

    try:
        # Resolve target to an IP address
        target_ip = socket.gethostbyname(clean_domain)
        logger.info(f"Phân giải thành công tên miền {clean_domain} -> IP: {target_ip}")
    except socket.gaierror:
        logger.error(f"Thất bại phân giải DNS cho {clean_domain}")
        return {"error": f"Không thể phân giải tên miền (Domain Resolution Failed): {clean_domain}"}

    open_ports = []
    logger.info(f"Tiến hành quét {len(ports)} cổng với {max_threads} luồng...")
    
    # ThreadPoolExecutor giúp gọi hàng chục/hàng trăm socket kết nối cùng lúc cực nhanh
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_single_port, target_ip, p) for p in ports]
        
        for future in futures:
            port, is_open = future.result()
            if is_open:
                logger.warning(f"[+] Phát hiện nắp cống Cổng {port} đang MỞ!")
                open_ports.append(port)
                
    logger.info(f"Hoạt động Quét Cổng hoàn tất. Tổng Mở: {len(open_ports)}")
    return {"ip": target_ip, "open_ports": sorted(open_ports)}

if __name__ == "__main__":
    # Internal module testing
    print("Testing port scanner module...")
    result = scan_ports("localhost", [21, 22, 80, 443, 3306, 5432, 8080])
    print(result)
