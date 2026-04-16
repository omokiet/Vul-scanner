# Sử dụng image Python phiên bản siêu nhẹ làm nền tảng
FROM python:3.11-slim

# Biến môi trường giúp Python không tạo ra các file .pyc (nhẹ hơn) 
# và hiển thị log ngay lập tức trên màn hình
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Thiết lập thư mục làm việc bên trong container
WORKDIR /app

# Copy file requirements.txt vào trước để tận dụng bộ đệm (cache) của Docker.
# Lần build sau nếu file này không đổi, bước này sẽ được Docker tự động bỏ qua (nhanh hơn).
COPY requirements.txt .

# Cài đặt các thư viện Python cần thiết
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn của bạn vào trong container
COPY . .

# Thông báo rằng ứng dụng sẽ chạy trên port 8501 (cổng mặc định của Streamlit)
EXPOSE 8501

# Lệnh sẽ được gọi khi container khởi động
CMD ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
