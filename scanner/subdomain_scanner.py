import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger("SubdomainScanner")

def enumerate_subdomains(domain):
    """
    Thực hiện Passive Subdomain Enumeration bằng cách truy vấn CSDL Chứng chỉ công khai (crt.sh).
    """
    # Chuẩn hóa domain cốt lõi
    domain = str(domain).strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).hostname
    domain = domain.split('/')[0]

    # Gọi API từ tổ chức Certificate Transparency
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info(f"Đang gọi API tĩnh crt.sh cho tên miền mẹ: {domain}")
    
    try:
        response = requests.get(url, timeout=12, verify=False)
        if response.status_code == 200:
            logger.info("Hoàn tất tải File dữ liệu gốc Array Json!")
            data = response.json()
            subdomains = set() # Sử dụng set để tự động chặn trùng lặp
            logger.info(f"Bắt đầu quy trình giải nén và lọc trên {len(data)} chứng chỉ lịch sử...")
            
            for entry in data:
                name_value = entry.get('name_value', '')
                # crt.sh đôi khi trả về nhiều subdomain chung 1 record ngăn cách bởi dòng mới
                for sub in name_value.split('\n'):
                    sub = sub.strip()
                    # Không trích xuất các Wildcard certs vì nó không phải là URL thực
                    if sub and not sub.startswith('*'):
                        subdomains.add(sub)
            
            logger.info(f"Thành công! Trích xuất {len(subdomains)} miền liên đới.")
            return {"domain": domain, "subdomains": sorted(list(subdomains))}
        else:
            logger.error(f"Thất bại lấy API. Code: {response.status_code}")
            return {"error": f"API crt.sh từ chối kết nối. Mã lỗi HTTP: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print(enumerate_subdomains("scanme.nmap.org"))
