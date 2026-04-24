import numpy as np
import logging
from typing import Dict, Tuple
from security_gate.core.config import settings

logger = logging.getLogger(__name__)

class RiskEngine:
    """Core Engine thực thi mô hình AHP & SAW cho Framework Security Gate."""
    
    def __init__(self):
        self.weights, self.cr_score, self.is_valid = self._calculate_and_verify_ahp()
        if not self.is_valid:
            logger.error(f"Ma trận AHP không nhất quán (CR={self.cr_score:.3f}).")

    def _calculate_and_verify_ahp(self) -> Tuple[np.ndarray, float, bool]:
        matrix = np.array(settings.AHP_MATRIX_RATIOS)
        n = matrix.shape[0]
        eig_val, eig_vec = np.linalg.eig(matrix)
        max_eig_val = np.max(eig_val.real)
        weights = eig_vec[:, np.argmax(eig_val.real)].real
        weights /= weights.sum()
        
        ci = (max_eig_val - n) / (n - 1) if n > 1 else 0
        ri = 0.90 # Tra bảng Saaty cho n=4
        cr = ci / ri if ri != 0 else 0
        return weights, cr, cr <= 0.1

    # =========================================================================
    # BỘ THÔNG DỊCH ĐIỂM (MAPPING RULES) - THEO WORKFLOW VÀ SCORING MATRIX MỚI
    # =========================================================================

    @staticmethod
    def map_cvss(cvss_raw: float, heuristic_flag: bool = False) -> float:
        """
        Luồng CV: Truy vấn Google OSV-Scanner (Package & Version)
        Quy đổi: Critical (0đ), High (2đ), Medium (5đ), Low (8đ), None (10đ)
        """
        if heuristic_flag: return 0.0
        try:
            cvss = float(cvss_raw)
        except ValueError:
            cvss = 0.0

        if cvss >= 9.0: return 0.0   # Critical
        if cvss >= 7.0: return 2.0   # High
        if cvss >= 4.0: return 5.0   # Medium
        if cvss > 0.0:  return 8.0   # Low
        return 10.0                  # None (Safe)

    @staticmethod
    def map_integrity(has_sig: bool, has_hash: bool, malware_found: bool) -> float:
        """
        Luồng CI: Quét YARA (mã độc) & Xác thực Hash/Signature
        Quy đổi: Chữ ký số (10đ), Chỉ Hash (6đ), Không xác thực (0đ). 
        Kill-switch: Có mã độc (0đ).
        """
        if malware_found: 
            return 0.0 # Phát hiện pattern mã độc từ YARA: 0 điểm tuyệt đối
        
        if has_sig:  
            return 10.0 # Có chữ ký số
        if has_hash: 
            return 6.0  # Chỉ có Hash (Đã điều chỉnh từ 9.0 -> 6.0 theo bảng)
        
        return 0.0      # Không xác thực

    @staticmethod
    def map_license(license_str: str) -> float:
        """
        Luồng CL: Trích xuất từ SBOM (Syft)
        Quy đổi: Permissive (MIT, Apache, GPL) -> 10đ. Không rõ/Không có -> 0đ.
        """
        if not license_str:
            return 0.0
            
        license_upper = str(license_str).upper()
        # Kiểm tra sự xuất hiện của các từ khóa license hợp lệ
        permissive_keywords = ["MIT", "APACHE", "GPL"]
        
        if any(keyword in license_upper for keyword in permissive_keywords):
            return 10.0
            
        return 0.0

    @staticmethod
    def map_maintenance(months_since_last_commit: float, num_maintainers: int, is_abandoned: bool = False) -> float:
        """
        Luồng CM: Truy vấn metadata từ GitHub/PyPI
        Công thức: CM = (M1 + M2) / 2
        - M1 (Thời gian commit): < 3 tháng (10đ); < 1 năm (5đ); > 1 năm (0đ)
        - M2 (Cộng đồng): > 5 maintainers (10đ); 1-5 maintainers (3đ)
        """
        if is_abandoned: 
            return 0.0
            
        # Tính M1: Thời gian commit cuối
        if months_since_last_commit < 3:
            m1 = 10.0
        elif months_since_last_commit <= 12: # < 1 năm
            m1 = 5.0
        else:
            m1 = 0.0
            
        # Tính M2: Hoạt động cộng đồng
        if num_maintainers > 5:
            m2 = 10.0
        elif num_maintainers >= 1: # Gom nhóm 1-5 maintainers vào mức 3đ để tránh lọt case
            m2 = 3.0
        else:
            m2 = 0.0
            
        # Trả về trung bình cộng
        return (m1 + m2) / 2.0

    # ==========================================
    # GIAI ĐOẠN TÍNH TOÁN TỔNG HỢP (SAW)
    # ==========================================
    
    def calculate_saw_score(self, final_scores: Dict[str, float]) -> float:
        """
        Tính điểm rủi ro tổng hợp R dựa trên trọng số AHP.
        Thứ tự array: [CV, CM, CI, CL]
        """
        # Đảm bảo array có điểm mặc định an toàn nếu pipeline bị thiếu data
        scores_array = np.array([
            final_scores.get('CV', 10.0),
            final_scores.get('CM', 10.0),
            final_scores.get('CI', 0.0),  # Mặc định 0 nếu không check được integrity
            final_scores.get('CL', 0.0)   # Mặc định 0 nếu không rõ license
        ])
        
        # Công thức: R = Σ (wi * si)
        r_score = np.dot(scores_array, self.weights)
        return round(float(r_score), 2)