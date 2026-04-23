# Hệ Thống Quét Lỗ Hổng Cơ Bản (Python Vulnerability Scanner)

## Tóm Tắt Dự Án (Overview)

Đây là một hệ thống rà quét điểm yếu máy chủ đầu cuối được viết hoàn toàn bằng Python, tích hợp giao diện người dùng trực quan trên nền tảng **Streamlit**. Công cụ đóng vai trò như một trạm kiểm soát tự động hóa, giúp quản trị viên dò tìm nhanh các khe hở bảo mật phổ biến nhất trên hạ tầng mạng và ứng dụng Web.

Dự án nhấn mạnh vào tính ứng dụng cốt lõi, loại bỏ sự phức tạp thừa thãi nhưng vẫn tích hợp các thuật toán rà soát nâng cao (như xử lý luồng đa nhiệm và thuật toán chống ảo ảnh SPA).

## Chức Năng Cốt Lõi (Core Features)

1. **Động Cơ Quét Mạng (Multi-threading Port Scanner):**
   - Quét đa luồng tìm kiếm các cổng mở (TCP) bằng socket.
   - Kết hợp nhận diện dịch vụ (Banner Grabbing) và liên kết tra cứu lỗ hổng trên NVD (CVE).
2. **Kiểm Tra Chứng Chỉ Bảo Mật (SSL/TLS Scanner):**
   - Xác thực trạng thái, ngày hết hạn và tính toàn vẹn của chứng chỉ SSL.
   - Cảnh báo sử dụng giao thức yếu (SSLv2, SSLv3, TLSv1).
3. **Kiểm tra Khoang Chứa HTTP (Security Headers Analyzer):**
   - Đọc thẻ chính sách bảo mật cấu hình, cảnh báo các lỗ hổng thiếu HSTS, X-Frame-Options, XSS Protection.
4. **Thám Thính Tài Nguyên Phân Cấp (Directory Fuzzing / Enumeration):**
   - Quét nhanh các tệp và thư mục ẩn (backup, db.sql, .env, admin panel) bằng Wordlist.
   - Tích hợp cơ chế phát hiện Catch-All Router (Soft 404 Detect) bằng so sánh kích thước tải trọng.
5. **Dò Tên Miền Phụ (Subdomain Enumerator):**
   - Thu thập thông tin tên miền phụ thụ động thông qua cơ sở dữ liệu Certificate Transparency (crt.sh).

## Công Nghệ Phát Triển (Tech Stack)

- **Ngôn Ngữ:** ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) `3.10+`
- **Thiết Kế Giao Diện UI:** ![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=Streamlit&logoColor=white) ![Pandas](https://img.shields.io/badge/Pandas-150458?style=flat-square&logo=pandas&logoColor=white)
- **Core Logic:** `socket` (Kết nối cấp thấp), `requests` (Truy xuất HTTP), `urllib.parse` (Hỗ trợ phân tích cú pháp).

## Tổ Chức Thư Mục (Directory Structure)

```text
Vul-scanner/
├── docs/                             # Bách khoa toàn thư chứa tài liệu nghiên cứu chuyên môn sâu
├── scanner/                          # Thư mục mã nguồn Động Cơ Quét Mạch
│   ├── port_scanner.py               # Thuật toán đa luồng dò Socket
│   ├── banner_scanner.py             # Trích xuất phiên bản Dịch Vụ và CVE Lookup
│   ├── ssl_scanner.py                # Phân tích trạng thái chứng chỉ SSL/TLS
│   ├── web_scanner.py                # Thuật toán HTTP Request / Baseline Fuzzing / Header Checks
│   └── subdomain_scanner.py          # Quét OSINT qua Certificate Transparency
├── main.py                           # Application File (Trái tim giao diện Streamlit)
├── docker-compose.yml                # Cấu hình container Docker
├── Dockerfile                        # File cấu hình build Image
├── requirements.txt                  # Gói phần mềm tiền đề Python
└── README.md                         # Tài liệu giới thiệu
```

## Hướng Dẫn Kích Hoạt (How To Run)

Dự án hỗ trợ 2 phương pháp khởi chạy: sử dụng Docker (khuyên dùng) hoặc chạy trực tiếp bằng Python (Môi trường ảo).

### Phương Pháp 1: Chạy bằng Docker (Khuyên Dùng)

Đây là cách triển khai nhanh gọn nhất dành cho những hệ thống cần đảm bảo tính thống nhất về môi trường. Bạn cần cài đặt sẵn Docker và Docker Compose.

1.  **Dùng lệnh Docker Compose để tự động xây dựng và vận hành:**
    ```bash
    docker-compose up -d --build
    ```
2.  Vào trình duyệt và truy cập `http://localhost:8501`.
3.  **(Tùy Chọn) Quản lý hệ thống container:**
    - Xem tiến trình Logs: `docker-compose logs -f`
    - Tắt và dọn dẹp hệ thống: `docker-compose down`

### Phương Pháp 2: Chạy bằng Native Python (Môi trường ảo)

Để công cụ hoạt động ổn định và không can thiệp vào Python máy chủ nền, vui lòng sử dụng Virtual Environment:

1.  **Khởi tạo và kích hoạt môi trường `.venv`:**

    ```bash
    # Dành cho Windows (PowerShell/CMD)
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

    # Dành cho macOS/Linux (Bash/Zsh)
    python3 -m venv .venv
    source .venv/bin/activate
    ```

2.  **Cài đặt các gói thư viện bảo mật và hiển thị bắt buộc:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Bật hệ thống máy trạm UI cục bộ:**
    ```bash
    streamlit run main.py
    ```
4.  Giao diện Terminal trở thành trạm điều hành (Stream Logs). Truy cập Dashboard qua địa chỉ `http://localhost:8501`.

## Tuyên Bố Pháp Lý Hệ Thống (Ethics & Legal)

Phần mềm phục vụ mục đích Đào tạo nhận thức An toàn Thông tin và Kiểm định nội bộ. Áp dụng mã trinh sát lên một hệ thống bất kỳ khi **CHƯA ĐƯỢC CHỦ SỞ HỮU ỦY QUYỀN** lập thời cấu thành hình sự Tội Phạm Tấn Công Mạng theo Pháp Luật.
Vui lòng sử dụng máy chủ nội mạng `127.0.0.1` hoặc scan test web `scanme.nmap.org` để kiểm thử một cách hợp pháp.
