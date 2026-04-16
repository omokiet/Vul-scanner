import streamlit as st
import pandas as pd
import urllib3
import logging
from scanner.port_scanner import scan_ports
from scanner.web_scanner import check_security_headers, enumerate_directories
from scanner.subdomain_scanner import enumerate_subdomains
from scanner.ssl_scanner import check_ssl_certificate

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)-12s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
main_logger = logging.getLogger("MainUI")

# Tắt cảnh báo Verify của InsecureRequest (Bởi vì tool quét có thể gặp domain chưa cert SSL)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Config giao diện cơ bản (Must be first Streamlit command)
st.set_page_config(page_title="Hệ thống Quét Lỗ Hổng Cơ Bản", page_icon="🛡️", layout="wide")

st.title("🛡️ Công Cụ Phân Tích Lỗ Hổng (Vulnerability Scanner)")
st.markdown("⚠️ Công cụ phục vụ đánh giá an toàn thông tin chuyên dụng. **Tuyệt đối không sử dụng trên hệ thống trái phép.**")

# ============= SIDEBAR ==============
st.sidebar.header("🎯 Mục Tiêu (Target)")
target = st.sidebar.text_input("Nhập Domain hoặc IP:", value="scanme.nmap.org")

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Cấu Hình Scan")
enable_port_scan = st.sidebar.checkbox("🔌 Bật Quét Cổng (Port Scan)", value=True)
port_range = st.sidebar.text_input("Gõ danh sách Port:", value="21, 22, 23, 80, 443, 3306, 8080", help="Các port cách nhau bởi dấu phẩy")

enable_header_scan = st.sidebar.checkbox("🌐 Kiểm tra HTTP Security Headers", value=True)
enable_ssl_scan = st.sidebar.checkbox("🔒 Kiểm tra Chứng Chỉ SSL/TLS", value=True)
enable_dir_scan = st.sidebar.checkbox("📂 Dò Thư Mục Web (Dir Fuzzing)", value=False)
enable_subdomain_scan = st.sidebar.checkbox("🔍 Dò Tên Miền Phụ (Subdomains)", value=False)

start_scan = st.sidebar.button("🚀 BẮT ĐẦU PHÂN TÍCH", type="primary", use_container_width=True)


# ============= MAIN APP AREA ==============
if start_scan:
    if not target.strip():
        st.error("❌ Vui lòng nhập mục tiêu hợp lệ!")
    else:
        # Biến chứa dữ liệu xuất CSV file lưu trữ
        export_logs = []
        
        # UI thông báo tiến trình
        st.info(f"Đang tiến hành truy vết và quét mục tiêu: **{target}**...")
        main_logger.info("===============================================")
        main_logger.info(f"🚀 BẮT ĐẦU CHIẾN DỊCH VUL-SCAN: {target}")
        main_logger.info("===============================================")
        
        # Tabs hiển thị kết quả (Giao diện đa nhiệm)
        tab1, tab5, tab2, tab3, tab4 = st.tabs(["🔌 Theo Dõi Port", "🔒 SSL/TLS", "🌐 Header HTTP", "📂 Khám Phá File", "🔍 Miền Phụ"])
        
        # 1. Quét Cổng (Port Scanning)
        with tab1:
            if enable_port_scan:
                with st.spinner("Đang kết nối Socket đến các cổng..."):
                    ports_to_scan = [int(p.strip()) for p in port_range.split(",") if p.strip().isdigit()]
                    port_results = scan_ports(target, ports_to_scan)
                    
                    if "error" in port_results:
                        st.error(f"Lỗi: {port_results['error']}")
                    else:
                        st.success(f"Kiểm tra IP: {port_results['ip']} hoàn tất.")
                        open_ports = port_results["open_ports"]
                        
                        if open_ports:
                            st.warning(f"Cảnh báo: Phát hiện {len(open_ports)} cổng đang mở kết nối ngoài!")
                            df_ports = pd.DataFrame({"Cổng Phát Hiện": open_ports, "Trạng Thái": ["MỞ"] * len(open_ports)})
                            st.dataframe(df_ports, use_container_width=True)
                            
                            for p in open_ports:
                                export_logs.append({"Loại Lỗ Hổng": "Port Mở", "Giá Trị": f"Port: {p}", "Trạng thái": "MỞ"})
                                
                            st.markdown("### 🕵️ Banners & Tra Cứu Lỗ Hổng (CVE)")
                            with st.spinner("Đang kết nối nhận dạng dịch vụ (Banner Grabbing)..."):
                                from scanner.banner_scanner import analyze_banners
                                banner_results = analyze_banners(port_results['ip'], open_ports)
                                
                                for r in banner_results:
                                    bn = r['banner']
                                    if not bn.startswith("Không nhận diện được"):
                                        st.write(f"- **Port {r['port']}**: `{bn}`")
                                        export_logs.append({"Loại Lỗ Hổng": "Banner/Version Dịch Vụ", "Giá Trị": bn, "Trạng thái": "THÔNG TIN"})
                                        if r['nvd_url']:
                                            st.markdown(f"  👉 [Tra cứu mã lỗ hổng (CVE) cho `{bn}` trên NVD]({r['nvd_url']})")
                                    else:
                                        st.write(f"- **Port {r['port']}**: *(Không rò rỉ phiên bản ứng dụng)*")
                        else:
                            st.success("Tên miền này đang phòng thủ tốt, không phát hiện cổng nào mở.")
            else:
                st.write("Module quét cổng đang tắt.")
                
        # Xử lý Phân tích SSL/TLS
        with tab5:
            if enable_ssl_scan:
                with st.spinner("Đang phân tích Chứng chỉ Bảo mật..."):
                    ssl_results = check_ssl_certificate(target)
                    
                    if ssl_results.get("error") and not ssl_results.get("vulnerabilities"):
                        st.error(f"Lỗi truy xuất SSL: {ssl_results['error']}")
                    else:
                        if ssl_results['is_valid']:
                            st.success(f"Kết nối SSL khả dụng! Giao thức: **{ssl_results['protocol']}**")
                        else:
                            st.warning(f"Chứng chỉ có vấn đề xác thực: {ssl_results.get('error', 'Không hợp lệ')}")
                            
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("### 📜 Thông Tin Cấp Phát")
                            st.info(
                                f"**Tên Miền Đăng Ký (Subject):**\n\n{ssl_results['subject']}\n\n"
                                f"**Tổ Chức Cấp Chứng Chỉ (Issuer):**\n\n{ssl_results['issuer']}\n\n"
                                f"**Thời gian Hết Hạn:**\n\n{ssl_results['expires_on']} *(Còn lại {ssl_results['days_left']} ngày)*"
                            )
                        with col2:
                            st.markdown("### ⚠️ Đánh Giá An Toàn")
                            vulns = ssl_results.get('vulnerabilities', [])
                            if vulns:
                                for v in vulns:
                                    st.error(f"Rủi ro: {v}")
                                    export_logs.append({"Loại Lỗ Hổng": "Rủi Ro SSL/TLS", "Giá Trị": v, "Trạng thái": "CẢNH BÁO"})
                            else:
                                st.success("Không phát hiện lỗ hổng hay giao thức lỗi thời (TLS/SSL).")
            else:
                st.write("Kiểm tra chứng chỉ SSL/TLS đang bị vô hiệu hóa.")

        # 2. Xử lý Phân tích HTTP
        with tab2:
            if enable_header_scan:
                with st.spinner("Đang phân tách HTTP Security Headers..."):
                    header_results = check_security_headers(target)
                    
                    if "error" in header_results:
                        st.error(f"Không thể kết nối vào Website để phân tích Web: {header_results['error']}")
                    else:
                        st.success(f"Kết nối Web thành công. Mã trạng thái (Status Code): **{header_results['status_code']}**. Hệ thống Web: **{header_results['server']}**")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("### ✅ Headers An Toàn Đã Có")
                            if header_results['present_headers']:
                                for h in header_results['present_headers']:
                                    st.write(f"- `{h}`")
                            else:
                                st.write("Không tìm thấy Header bảo mật nào!")
                        
                        with col2:
                            st.markdown("### ❌ Cảnh Báo: Headers Bị Thiếu")
                            if header_results['missing_headers']:
                                for h in header_results['missing_headers']:
                                    st.error(f"Lỗ hổng cấu hình: Thiếu thẻ `{h}`")
                                    export_logs.append({"Loại Lỗ Hổng": "Khuyết HTTP Header", "Giá Trị": h, "Trạng thái": "THIẾU SÓT"})
                            else:
                                st.success("Website triển khai Headers rất hoàn hảo.")
            else:
                st.write("Module phát hiện Header đang tắt.")
                
        # 3. Quét Thư Mục
        with tab3:
            if enable_dir_scan:
                with st.spinner("Đang Bruteforce (Dò quét) các thư mục ẩn..."):
                    dir_results = enumerate_directories(target)
                    
                    if not dir_results:
                        st.success("Không phát hiện thư mục gốc nhạy cảm nào bị lộ lọt.")
                    else:
                        st.warning(f"Thông báo nguy hại: Tồn tại khả năng rò rỉ {len(dir_results)} đường dẫn ẩn!")
                        df_dirs = pd.DataFrame(dir_results)
                        st.dataframe(df_dirs, use_container_width=True)
                        for d in dir_results:
                                export_logs.append({"Loại Lỗ Hổng": "Lộ Đường Dẫn Mạng", "Giá Trị": d['path'], "Trạng thái": str(d['status'])})
            else:
                st.write("Module dò đường dẫn đang bị vô hiệu hóa.")
                
        # 4. Quét Tên Miền Phụ (Subdomains)
        with tab4:
            if enable_subdomain_scan:
                with st.spinner("Đang truy vấn CSDL Chứng chỉ crt.sh toàn cầu..."):
                    sub_results = enumerate_subdomains(target)
                    
                    if "error" in sub_results:
                        st.error(f"Gặp lỗi khi truy xuất API: {sub_results['error']}")
                    else:
                        subdomains = sub_results.get("subdomains", [])
                        if not subdomains:
                            st.success(f"Không tìm thấy tên miền phụ nào liên đới tới `{sub_results.get('domain')}`.")
                        else:
                            st.warning(f"Đã trích xuất thành công {len(subdomains)} tên miền phụ liên quan!")
                            df_subs = pd.DataFrame({"Subdomain Phát Hiện": subdomains})
                            st.dataframe(df_subs, use_container_width=True)
                            for sub in subdomains:
                                export_logs.append({"Loại Lỗ Hổng": "Miền Phụ Công Khai", "Giá Trị": sub, "Trạng thái": "CẢNH BÁO"})
            else:
                st.write("Module dò tên miền phụ đang tắt.")

        # Kết thúc quy trình, cung cấp file trích xuất xuất hiện khi hoàn thành
        st.markdown("---")
        st.subheader("📥 Sao Lưu Báo Cáo Hệ Thống")
        if export_logs:
            df_export = pd.DataFrame(export_logs)
            csv = df_export.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📁 Tải file kết quả CSV",
                data=csv,
                file_name='vulnerability_report.csv',
                mime='text/csv',
            )
        else:
            st.write("Quét hoàn tất và không có lỗ hổng lớn nào bị phát hiện để xuất file.")
