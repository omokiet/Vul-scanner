# Hệ Thống Quét Lỗ Hổng Cơ Bản (Python Vulnerability Scanner)

## Tóm Tắt Dự Án (Overview)
Đây là một hệ thống rà quét điểm yếu máy chủ đầu cuối được viết hoàn toàn bằng Python, tích hợp giao diện người dùng trực quan trên nền tảng **Streamlit**. Công cụ đóng vai trò như một trạm kiểm soát tự động hóa, giúp quản trị viên dò tìm nhanh các khe hở bảo mật phổ biến nhất trên hạ tầng mạng và ứng dụng Web.

Dự án nhấn mạnh vào tính ứng dụng cốt lõi, loại bỏ sự phức tạp thừa thãi nhưng vẫn tích hợp các thuật toán rà soát nâng cao (như xử lý luồng đa nhiệm và thuật toán chống ảo ảnh SPA).

## Chức Năng Cốt Lõi (Core Features)
1. **Động Cơ Quét Mạng (Multi-threading Port Scanner):**
   * Hoạt động dưới Tầng Giao Vận (TCP). Quét tìm các "Cánh Cửa" mạng mở hớ hênh (VD như SSH, Database, FTP).
   * Sử dụng ThreadPoolExecutor phân tải công việc lên cực hạn, giúp trích xuất IP và Ping dò tìm siêu tốc.
   * Tự động tiền xử lý tên miền chống sập bộ máy phân giải (DNS Error Sanitizing).
2. **Kiểm Kiểm Khoang Chứa HTTP (Security Headers Analyzer):**
   * Đọc thẻ chính sách bảo mật cấu hình. Đưa ra lệnh cảnh báo thiếu hụt chống cướp phiên, Downgrade Attack (HSTS, XSS Protection).
3. **Thám Thính Tài Nguyên Phân Cấp (Directory Fuzzing / Enumeration):**
   * Đưa ăng ten cắm thẳng vào máy trạm tìm hệ thống nhạy cảm (Tệp Backup, Mật khẩu hệ thống bị công khai .env).
   * **[Tính Năng Cao Cấp]** Thuật Toán Nhận Diện Catch-All Routing (Soft 404 Detect): Áp dụng phương thức chênh lệch tải trọng (Baseline Length Comparison) dập tắt vĩnh viễn báo cáo Rác trên các hệ Web hiện đại (React/Next).

## Công Nghệ Phát Triển (Tech Stack)
*   **Ngôn Ngữ:** ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) `3.10+`
*   **Thiết Kế Giao Diện UI:** ![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=Streamlit&logoColor=white) ![Pandas](https://img.shields.io/badge/Pandas-150458?style=flat-square&logo=pandas&logoColor=white)
*   **Core Logic:** `socket` (Kết nối cấp thấp), `requests` (Truy xuất HTTP), `urllib.parse` (Hỗ trợ phân tích cú pháp).

## Tổ Chức Thư Mục (Directory Structure)
```text
Vul-scanner/
├── docs/                             # Bách khoa toàn thư chứa tài liệu nghiên cứu chuyên môn sâu
│   ├── port_scanning.md              # Khái niệm Port, Rủi ro Đánh cắp, Khai thác lỗ hổng CVE
│   ├── web_scanning.md               # Kiến thức Web Security Headers, Soft 404 Detect Method
│   └── troubleshooting_networking.md # Báo cáo cấp thấp về Giao thức Tầng mạng (DNS)
├── scanner/                          # Thư mục mã nguồn Động Cơ Quét Mạch
│   ├── port_scanner.py               # Thuật toán đa luồng đi dò Socket
│   └── web_scanner.py                # Thuật toán HTTP Request / Baseline Fuzzing Filter
├── main.py                           # Application File (Trái tim giao diện)
├── requirements.txt                  # Gói phần mềm tiền đề
└── README.md                         # (Tài liệu giới thiệu bạn đang đọc)
```

## Hướng Dẫn Kích Hoạt (How To Run)
Để công cụ hoạt động ổn định và không can thiệp vào Python hệ thống, vui lòng cài đặt bằng Môi trường Ảo (Virtual Environment):

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
3.  **Bật hệ thống máy trạm UI cục bộ (Web Application):**
    ```bash
    streamlit run main.py
    ```
4. Giao diện Terminal lập tức sẽ trở thành trạm điều hành (Stream Logs). Trình duyệt sẽ tự động kích hoạt bảng điều khiển Web Quét Lỗ Hổng tại địa chỉ `http://localhost:8501`.

## Tuyên Bố Pháp Lý Hệ Thống (Ethics & Legal)
Phần mềm phục vụ mục đích Đào tạo nhận thức An toàn Thông tin và Kiểm định nội bộ. Áp dụng mã trinh sát lên một hệ thống bất kỳ khi **CHƯA ĐƯỢC CHỦ SỞ HỮU ỦY QUYỀN** lập thời cấu thành hình sự Tội Phạm Tấn Công Mạng theo Pháp Luật.
Vui lòng sử dụng máy chủ nội mạng `127.0.0.1` hoặc máy dò huấn luyện `scanme.nmap.org` để kiểm thử chính xác và hợp pháp 100%.
