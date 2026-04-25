# Luan_van_TN
# 🛡️ Software Supply Chain Security Assessment (ASVS 5.0.0)

[![Security Status](https://img.shields.io/badge/Security-OWASP%20ASVS%205.0.0-orange)](https://owasp.org/www-project-application-security-verification-standard/)
[![Language](https://img.shields.io/badge/Language-Python%20%7C%20C%23-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Dự án nghiên cứu xây dựng quy trình đánh giá an ninh chuỗi cung ứng phần mềm mã nguồn mở. Đây là nội dung thuộc luận văn tốt nghiệp chuyên ngành **An toàn thông tin** - **Đại học Cần Thơ**.

---

## 📖 Tổng quan đề tài
Đề tài tập trung vào việc định lượng hóa các yêu cầu bảo mật của **OWASP ASVS 5.0.0** để đánh giá rủi ro cho các thư viện mã nguồn mở (OSS). Quy trình sử dụng các mô hình toán học để đưa ra điểm số khách quan về mức độ tin cậy của thành phần phần mềm.

### 🌟 Điểm nổi bật
- **Mô hình AHP & SAW:** Tính toán trọng số động và điểm rủi ro tổng hợp.
- **Phân tích Integrity:** Kiểm tra chữ ký số và mã băm (Digital Signatures & Hash).
- **Quét mã độc:** Tích hợp luật YARA và phân tích heuristic.
- **Cơ chế Fallback:** Tối ưu hóa điểm số cho các thư viện chuẩn khi thiếu dữ liệu (mặc định 10.0).

---

## 📂 Cấu trúc kho lưu trữ
| Thư mục/Tệp | Mô tả |
| :--- | :--- |
| 📁 `Bao_cao_chinh_thuc` | Tài liệu báo cáo chi tiết (PDF/Docx). |
| 📁 `LV_Quantitative_open_source` | Mã nguồn chương trình đánh giá (Risk Engine). |
| 📦 `Luan_van_backup.rar` | Bản sao lưu toàn bộ project. |
| 📄 `README.md` | Hướng dẫn sử dụng dự án. |

---

## 🛠 Cài đặt và Sử dụng
1. **Yêu cầu hệ thống:** Python 3.12
2. **Cài đặt thư viện:**
   ```bash
   pip install -r requirements.txt

---

## Chạy chương trình:
   ```bash
   python main.py

🧪 Dữ liệu thử nghiệm (Test Samples)
Để kiểm chứng độ chính xác của quy trình đánh giá, các mẫu thử nghiệm bao gồm các thư viện an toàn và các mẫu có lỗ hổng (như OWASP Juice Shop, Apache Log4j) đã được chuẩn bị.

[!IMPORTANT]
Tải mã nguồn và dữ liệu test tại đây:
🔗 Download Test Samples & Source Code

📊 Phương pháp đánh giá rủi ro
Quy trình áp dụng ma trận so sánh cặp (AHP) để xác định tầm quan trọng của các tiêu chí:

CV (Vulnerability): Điểm lỗ hổng bảo mật.

CM (Maintenance): Mức độ duy trì dự án.

CI (Integrity): Tính toàn vẹn của gói phần mềm.

CL (License): Rủi ro về mặt pháp lý/giấy phép.
