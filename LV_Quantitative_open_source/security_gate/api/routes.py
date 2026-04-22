# (Giữ nguyên các import và thiết lập Singleton từ code gốc)
import os, uuid, json, shutil, logging, traceback
import numpy as np
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, Depends, Header, HTTPException, status, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import asyncio
from fastapi import BackgroundTasks
from security_gate.database.session import get_db
from security_gate.database.models import ScanReport, Project
from security_gate.core.risk_engine import RiskEngine
from security_gate.modules.ingestion import IngestionModule
from security_gate.modules.analysis import AnalysisModule
from security_gate.modules.exporter import ReportExporter
from security_gate.core.config import settings
from security_gate.schemas.reports import ScanReportResponse

logger = logging.getLogger(__name__)
router = APIRouter()
SCAN_PROGRESS = {}
engine = RiskEngine()
ingestion_module = IngestionModule()
analysis_module = AnalysisModule(engine)
exporter_module = ReportExporter(engine)

UPLOAD_DIR = settings.INPUT_DIR
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def get_secure_temp_path(filename: str, prefix: str = "scan_") -> Path:
    safe_name = "".join(c for c in filename if c.isalnum() or c in " ._-").strip()
    if not safe_name: safe_name = "artifact.bin"
    return UPLOAD_DIR / f"{prefix}{uuid.uuid4().hex[:8]}_{safe_name}"

def sanitize_for_json(obj):
    # (Hàm giữ nguyên)
    if isinstance(obj, dict): return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list): return [sanitize_for_json(v) for v in obj]
    elif isinstance(obj, np.integer): return int(obj)
    elif isinstance(obj, np.floating): return float(obj)
    elif isinstance(obj, np.bool_): return bool(obj)
    elif isinstance(obj, np.ndarray): return sanitize_for_json(obj.tolist())
    return obj

# ==========================================
# 1. TASK DỌN DẸP CHẠY NGẦM (CÁCH 1)
# ==========================================
async def cleanup_progress_task(tracking_id: str):
    """Đợi 60 giây để UI hoàn tất animation rồi mới xóa khỏi RAM"""
    await asyncio.sleep(60)
    if tracking_id in SCAN_PROGRESS:
        del SCAN_PROGRESS[tracking_id]
        logger.info(f"🗑️ Đã giải phóng bộ nhớ cho phiên quét: {tracking_id}")

# ==========================================
# 2. API THEO DÕI TRẠNG THÁI
# ==========================================
@router.get("/api/v1/scan/status/{tracking_id}")
async def get_scan_status(tracking_id: str):
    """Endpoint để Frontend cập nhật thanh tiến trình ngang"""
    return SCAN_PROGRESS.get(tracking_id, {"step": 1, "message": "Đang khởi tạo quy trình..."})

# ==========================================
# 3. API QUÉT CHÍNH (MANUAL SCAN)
# ==========================================
@router.post("/api/v1/scan", response_model=ScanReportResponse)
async def scan_artifact(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_id: int = Form(...),
    tracking_id: str = Form(None), 
    db: Session = Depends(get_db)
):
    def update_progress(step, msg):
        if tracking_id:
            SCAN_PROGRESS[tracking_id] = {"step": step, "message": msg}

    file_path = None
    try:
        # --- GIAI ĐOẠN 1: TIẾP NHẬN (25%) ---
        update_progress(1, f"Đang tiếp nhận và kiểm tra Artifact: {file.filename}")
        await asyncio.sleep(0.2) # Delay nhỏ để UI trượt mượt
        
        project_obj = db.query(Project).filter(Project.id == project_id).first()
        if project_obj and getattr(project_obj, 'is_locked', False):
            if tracking_id in SCAN_PROGRESS: del SCAN_PROGRESS[tracking_id]
            raise HTTPException(status_code=403, detail="Dự án đã bị Admin khóa.")

        file_path = get_secure_temp_path(file.filename, prefix="manual_")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # --- GIAI ĐOẠN 2: TRÍCH XUẤT SBOM (50%) ---
        update_progress(2, "Đang tiến hành trích xuất SBOM và định danh thành phần...")
        await asyncio.sleep(0.2)
        ingestion_data = ingestion_module.process_artifact(str(file_path))
        
        
        # --- GIAI ĐOẠN 3: PHÂN TÍCH RỦI RO (75%) ---
        update_progress(3, "Đang chạy Engine phân tích rủi ro đa chiều (OWASP ASVS)...")
        await asyncio.sleep(0.2)
        analysis_result = analysis_module.analyze(ingestion_data)
        clean_analysis_result = sanitize_for_json(analysis_result)
        
        # --- GIAI ĐOẠN 4: LƯU QUYẾT ĐỊNH (100%) ---
        update_progress(4, "Đang tổng hợp báo cáo và xác nhận phán quyết...")
        
        # [LOGIC NGHIỆP VỤ GỐC GIỮ NGUYÊN]
        original_filename = file.filename
        clean_analysis_result['artifact'] = original_filename 
        has_blind_spot = any(comp.get("is_blind_spot", False) for comp in clean_analysis_result.get("details", []))
        final_score = float(clean_analysis_result.get('final_score', 0.0))
        
        if final_score >= 8.0:
            decision = "PENDING_REVIEW" if has_blind_spot else "APPROVED"
        elif final_score >= 5.0:
            decision = "PENDING"
        else:
            decision = "REJECTED"

        new_report = ScanReport(
            project_id=project_id,
            artifact_name=original_filename, 
            hash_sha256=clean_analysis_result.get('hash', ''),
            score_cv=float(clean_analysis_result['weakest_link']['scores'].get('CV', 0)),
            score_cm=float(clean_analysis_result['weakest_link']['scores'].get('CM', 0)),
            score_ci=float(clean_analysis_result['weakest_link']['scores'].get('CI', 0)),
            score_cl=float(clean_analysis_result['weakest_link']['scores'].get('CL', 0)),
            final_score=final_score,
            decision=decision
        )
        db.add(new_report)
        db.commit()
        db.refresh(new_report)

        report_blob_path = settings.REPORT_DIR / f"full_audit_{new_report.id}.json"
        with open(report_blob_path, "w", encoding="utf-8") as f:
            json.dump(clean_analysis_result, f, ensure_ascii=False, indent=4)

        weakest_data = clean_analysis_result.get('weakest_link')
        weakest_component_name = weakest_data.get('name', 'Không xác định') if isinstance(weakest_data, dict) else str(weakest_data)
        weakest_scores = weakest_data.get('scores', {'CV':0,'CI':0,'CM':0,'CL':0}) if isinstance(weakest_data, dict) else {'CV':0,'CI':0,'CM':0,'CL':0}

        # Đăng ký dọn dẹp bộ nhớ sau khi trả phản hồi
        if tracking_id:
            background_tasks.add_task(cleanup_progress_task, tracking_id)

        return {
            "report_id": new_report.id,
            "artifact_name": new_report.artifact_name,
            "hash_sha256": new_report.hash_sha256,
            "final_score": new_report.final_score,
            "decision": new_report.decision,
            "weakest_link": weakest_component_name,
            "scores": weakest_scores 
        }

    except Exception as e:
        logger.error(traceback.format_exc())
        if tracking_id in SCAN_PROGRESS: del SCAN_PROGRESS[tracking_id]
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Ở đây chỉ xóa file vật lý, không xóa trạng thái
        if file_path and file_path.exists(): 
            file_path.unlink()
        if 'ingestion_data' in locals() and 'extract_path' in ingestion_data:
            ingestion_module.cleanup_artifact(ingestion_data['extract_path'])


@router.post("/api/v1/cicd/scan")
async def cicd_automated_scan(
    file: UploadFile = File(...),
    project_id: int = Form(...),
    x_api_key: str = Header(None), 
    db: Session = Depends(get_db)
):
    # Xác thực API Key
    expected_key = os.getenv("PIPELINE_SECRET_KEY")
    if not expected_key or x_api_key != expected_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Xác thực thất bại. API Key không hợp lệ.")

    # [TÍNH NĂNG MỚI]: Block luôn CI/CD nếu dự án đang bị khóa
    project_obj = db.query(Project).filter(Project.id == project_id).first()
    if project_obj and getattr(project_obj, 'is_locked', False):
        raise HTTPException(status_code=403, detail="Dự án đã bị khóa. CI/CD Pipeline bị hủy bỏ.")

    # (Phần xử lý file dưới này GIỮ NGUYÊN theo code gốc của bạn...)
    upload_path = get_secure_temp_path(file.filename, prefix="cicd_")
    
    # ... [Phần thân hàm quét CI/CD giữ nguyên] ...
    
# ... [Phần Export API giữ nguyên] ...

    try:
        with open(upload_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        ingestion_data = ingestion_module.process_artifact(str(upload_path))
        analysis_data = analysis_module.analyze(ingestion_data)
        
        if not analysis_data or 'final_score' not in analysis_data:
            raise ValueError("Không tìm thấy thành phần mã nguồn hợp lệ để phân tích.")

        clean_analysis_data = sanitize_for_json(analysis_data)
        
        # [SỬA LỖI UX]: Ghi đè tên cho chuẩn CI/CD
        original_filename = file.filename
        clean_analysis_data['artifact'] = original_filename

        # [KIẾN TRÚC MỚI]: Bắt tín hiệu "Điểm mù dữ liệu" cho luồng CI/CD
        has_blind_spot = any(comp.get("is_blind_spot", False) for comp in clean_analysis_data.get("details", []))

        score = float(clean_analysis_data['final_score'])
        weakest = clean_analysis_data.get('weakest_link', {}).get('scores', {'CV': 0, 'CM': 0, 'CI': 0, 'CL': 0})
        
        # [PHÁN QUYẾT HUMAN-IN-THE-LOOP]
        if score >= 8.0:
            if has_blind_spot:
                status_decision = "PENDING_REVIEW" 
            else:
                status_decision = "APPROVED"
        elif score >= 5.0:
            status_decision = "PENDING"
        else:
            status_decision = "REJECTED"

        db_report = ScanReport(
            project_id=project_id,
            artifact_name=f"[CI/CD] {original_filename}", 
            hash_sha256=ingestion_data.get('hash', ''),
            score_cv=float(weakest.get('CV', 0)),
            score_cm=float(weakest.get('CM', 0)),
            score_ci=float(weakest.get('CI', 0)),
            score_cl=float(weakest.get('CL', 0)),
            final_score=score,
            decision=status_decision
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        report_blob_path = settings.REPORT_DIR / f"full_audit_{db_report.id}.json"
        with open(report_blob_path, "w", encoding="utf-8") as f:
            json.dump(clean_analysis_data, f, ensure_ascii=False, indent=4)
        
        # CI/CD passed nếu điểm >= 5.0 (Cho phép cảnh báo nhưng không block pipeline cứng)
        is_passed = score >= 5.0 
        
        return {
            "status": "success",
            "ci_cd_passed": is_passed,
            "risk_score": score,
            "decision": status_decision,
            "details": "Bị chặn bởi Security Gate." if not is_passed else "Vượt qua Security Gate.",
            "weakest_component": clean_analysis_data.get('weakest_link')
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"CRITICAL ERROR in /cicd/scan:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Lỗi CI/CD Worker nội bộ.")
        
    finally:
        if upload_path.exists():
            upload_path.unlink()
        if 'ingestion_data' in locals() and 'extract_path' in ingestion_data:
            ingestion_module.cleanup_artifact(ingestion_data['extract_path'])

# ==========================================
# 3. API XUẤT BÁO CÁO ĐA ĐỊNH DẠNG
# ==========================================
@router.get("/api/v1/export/{report_id}")
async def export_audit_report(
    report_id: int, 
    format: str = Query("pdf", description="Định dạng xuất: pdf, word, excel"), 
    db: Session = Depends(get_db)
):
    report = db.query(ScanReport).filter(ScanReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Không tìm thấy báo cáo.")

    report_blob_path = settings.REPORT_DIR / f"full_audit_{report.id}.json"
    
    if report_blob_path.exists():
        with open(report_blob_path, "r", encoding="utf-8") as f:
            analysis_data = json.load(f)
    else:
        raise HTTPException(status_code=404, detail="Dữ liệu chi tiết của phiên quét này đã bị xóa hoặc mất mát.")

    try:
        file_path = exporter_module.export_report(analysis_data, format_type=format.lower())
        return FileResponse(
            path=file_path, 
            filename=file_path.name,
            media_type="application/octet-stream"
        )
    except Exception as e:
        logger.error("LỖI EXPORT FILE:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Lỗi tạo file: {str(e)}")