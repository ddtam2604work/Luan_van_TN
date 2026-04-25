# 🛡️ Software Supply Chain Security Assessment (ASVS 5.0.0)

<div align="center">

[![Security Status](https://img.shields.io/badge/Security-OWASP%20ASVS%205.0.0-orange?style=for-the-badge)](https://owasp.org/www-project-application-security-verification-standard/)
[![Language](https://img.shields.io/badge/Language-Python%203.12%20%7C%20C%23-blue?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

## 📝 Giới thiệu
Dự án nghiên cứu xây dựng quy trình đánh giá an ninh chuỗi cung ứng phần mềm mã nguồn mở. Đây là nội dung thuộc luận văn tốt nghiệp chuyên ngành **An toàn thông tin** - **Đại học Cần Thơ**.

---

## 📖 Tổng quan đề tài
Đề tài tập trung vào việc định lượng hóa các yêu cầu bảo mật của **OWASP ASVS 5.0.0** để đánh giá rủi ro cho các thư viện mã nguồn mở (OSS). Quy trình sử dụng các mô hình toán học để đưa ra điểm số khách quan về mức độ tin cậy của thành phần phần mềm.

### 🌟 Điểm nổi bật
* **Mô hình AHP & SAW:** Tính toán trọng số động và điểm rủi ro tổng hợp thông qua ma trận so sánh cặp.
* **Phân tích Integrity:** Kiểm tra chuyên sâu chữ ký số và mã băm (Digital Signatures & Hash Verification).
* **Quét mã độc:** Tích hợp luật YARA và các kỹ thuật phân tích heuristic để phát hiện mã độc thực thi.
* **Cơ chế Fallback:** Tối ưu hóa điểm số cho các thư viện chuẩn khi thiếu dữ liệu (mặc định đạt mức an toàn 10.0).

---

## 📂 Cấu trúc kho lưu trữ
| Thư mục/Tệp | Mô tả |
| :--- | :--- |
| 📁 `Bao_cao_chinh_thuc` | Tài liệu báo cáo chi tiết luận văn (PDF/Docx). |
| 📁 `LV_Quantitative_open_source` | Mã nguồn chính của Risk Engine và công cụ đánh giá. |
| 📦 `Luan_van_backup.rar` | Bản sao lưu dự phòng toàn bộ project. |
| 📄 `LICENSE` | Giấy phép sử dụng MIT. |
| 📄 `README.md` | Hướng dẫn và thông tin tổng quan. |

---

## 🧪 Dữ liệu thử nghiệm (Test Samples)
Để kiểm chứng độ chính xác của quy trình, dự án sử dụng các mẫu thử nghiệm thực tế bao gồm các thư viện an toàn và các mẫu chứa lỗ hổng bảo mật nổi tiếng (như **OWASP Juice Shop**, **Apache Log4j**).

> [!IMPORTANT]
> **Tải mã nguồn và dữ liệu test tại đây:** [Google Drive Link](https://drive.google.com/file/d/19f2Z2d5O48jJCUw8a_4qxF2QcB65udhQ/view?usp=drive_link)

---

## 📊 Phương pháp đánh giá rủi ro
Quy trình áp dụng ma trận so sánh cặp (**Analytical Hierarchy Process - AHP**) để xác định trọng số cho 4 tiêu chí cốt lõi:

| Chỉ số | Mô tả tiêu chí |
| :--- | :--- |
| 🛡️ **CV** (Vulnerability) | Đánh giá dựa trên điểm số lỗ hổng bảo mật đã công bố. |
| ⚙️ **CM** (Maintenance) | Đo lường mức độ hoạt động và duy trì của cộng đồng phát triển. |
| 🔒 **CI** (Integrity) | Xác minh tính toàn vẹn thông qua cơ chế chữ ký và checksum. |
| 📜 **CL** (License) | Phân tích rủi ro về mặt pháp lý và các loại giấy phép đi kèm. |

---

## 🛠 Cài đặt và Sử dụng

### 1. Yêu cầu hệ thống
* **Python:** Phiên bản 3.12 trở lên.
* **.NET Environment:** Dành cho các module hỗ trợ viết bằng C#.

### 2. Cài đặt thư viện
```bash
pip install -r requirements.txt
