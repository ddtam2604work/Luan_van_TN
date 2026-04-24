import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

# ==============================================================
# 1. CẤU HÌNH DỮ LIỆU THỰC NGHIỆM
# ==============================================================
# Trong thực tế, em cần một danh sách các tệp và bản chất thực của chúng
# 1: Nguy hiểm (Malicious/Vulnerable), 0: An toàn (Safe)
GROUND_TRUTH = {
    "apache-log4j-2.14.1.zip": 1,
    "commander.js-master.zip": 0,
    "requests-2.25.1.whl": 0,
    "malicious-package-test.zip": 1,
    # Em thêm danh sách 170 tệp của em vào đây...
}

REPORTS_DIR = "data/"
THRESHOLD = 5.0 # Ngưỡng ra quyết định [cite: 1463, 1531]

def evaluate_framework():
    results = []
    y_true = []
    y_pred = []

    # Quét toàn bộ file JSON trong thư mục báo cáo
    for filename in os.listdir(REPORTS_DIR):
        if filename.endswith(".json"):
            with open(os.path.join(REPORTS_DIR, filename), 'r') as f:
                data = json.load(f)
                
                artifact = data.get("artifact")
                score = data.get("final_score", 0)
                
                # Dự đoán của Framework: 1 (Rejected) nếu score < 5.0
                prediction = 1 if score < THRESHOLD else 0
                
                # Lấy nhãn thực tế từ từ điển GROUND_TRUTH
                # Nếu không có trong danh sách, mặc định là 0 (hoặc bỏ qua)
                actual = GROUND_TRUTH.get(artifact, 0)
                
                results.append({
                    "Artifact": artifact,
                    "Final Score": score,
                    "Prediction": "REJECTED" if prediction == 1 else "APPROVED",
                    "Actual Status": "DANGEROUS" if actual == 1 else "SAFE"
                })
                
                y_true.append(actual)
                y_pred.append(prediction)

    # 2. Xuất dữ liệu ra file CSV (để mở bằng Excel)
    df = pd.DataFrame(results)
    df.to_csv("evaluation_summary.csv", index=False, encoding='utf-8-sig')
    print("--- Đã xuất file evaluation_summary.csv ---")

    # 3. Vẽ Ma trận nhầm lẫn
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Pass (Safe)', 'Reject (Danger)'],
                yticklabels=['Actual Safe', 'Actual Danger'])
    
    plt.title(f'MA TRẬN NHẦM LẪN - THỰC NGHIỆM TRÊN {len(y_true)} MẪU', fontsize=14, fontweight='bold')
    plt.xlabel('Dự đoán từ Framework', fontsize=12)
    plt.ylabel('Bản chất thực tế', fontsize=12)
    
    # Lưu ảnh minh chứng cho báo cáo 
    plt.savefig('confusion_matrix_v2.png', dpi=300)
    print("--- Đã lưu ảnh confusion_matrix_v2.png ---")
    plt.show()

if __name__ == "__main__":
    # Đảm bảo thư mục tồn tại trước khi chạy
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    evaluate_framework()