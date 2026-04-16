import ssl
import socket
from datetime import datetime

def check_ssl_certificate(hostname, port=443):
    """
    Kết nối và kiểm tra chứng chỉ SSL/TLS của mục tiêu.
    :param hostname: Tên miền hoặc IP
    :param port: Cổng quét (Mặc định 443)
    :return: dict chứa thông tin chứng chỉ hoặc báo lỗi
    """
    # Xử lý nếu người dùng nhập IP hoặc domain (loại bỏ http/https nếu có)
    clean_host = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    context = ssl.create_default_context()
    
    result = {
        "hostname": clean_host,
        "is_valid": False,
        "subject": "",
        "issuer": "",
        "expires_on": "",
        "days_left": 0,
        "protocol": "",
        "error": None,
        "vulnerabilities": []
    }
    
    try:
        with socket.create_connection((clean_host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                protocol = ssock.version()
                cert = ssock.getpeercert()
                
                result['protocol'] = protocol
                result['is_valid'] = True
                
                # Check weak protocols
                if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    result['vulnerabilities'].append(f"Giao thức yếu: {protocol}")
                
                # Parse Subject
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                result['subject'] = subject_dict.get('commonName', 'Không xác định')
                
                # Parse Issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Không xác định'))
                
                # Parse Expiration
                expires = cert.get('notAfter')
                if expires:
                    # 'notAfter' format typically 'May 23 12:00:00 2024 GMT'
                    try:
                        expires_date = datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')
                        result['expires_on'] = expires_date.strftime('%d/%m/%Y')
                        
                        days_left = (expires_date - datetime.utcnow()).days
                        result['days_left'] = days_left
                        
                        if days_left <= 0:
                            result['vulnerabilities'].append("Chứng chỉ đã hết hạn!")
                        elif days_left < 30:
                            result['vulnerabilities'].append(f"Chứng chỉ sắp hết hạn (còn {days_left} ngày).")
                    except Exception:
                        result['expires_on'] = str(expires)
                        
    except ssl.SSLCertVerificationError as e:
         # Failed verification (self-signed, expired, etc.)
         result['error'] = f"Chứng chỉ không hợp lệ: {e.verify_message}"
         result['vulnerabilities'].append("Không thể xác minh chứng chỉ (Self-signed hoặc lỗi chuỗi tín nhiệm)")
    except Exception as e:
        result['error'] = f"Không trích xuất được SSL (Hoặc Port {port} đóng): {str(e)}"
        
    return result
