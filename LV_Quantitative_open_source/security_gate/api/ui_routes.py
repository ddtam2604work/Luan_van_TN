# Tệp: security_gate/api/ui_routes.py
import os
import logging
import traceback
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Form, status, HTTPException, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from security_gate.database.session import get_db
from security_gate.database.models import AuditLog, User, Organization, Project, ScanReport, UserRole
from security_gate.schemas.users import ProjectResponseSchema


logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="security_gate/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==========================================
# 1. TRANG CHỦ & ROUTE CHUNG
# ==========================================
@router.get("/", response_class=HTMLResponse)
async def serve_home(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if user_id and db.query(User).filter(User.id == user_id).first():
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)
    
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 2. XÁC THỰC: ĐĂNG NHẬP, ĐĂNG KÝ, ĐĂNG XUẤT
# ==========================================
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
async def login_action(
    request: Request, 
    email: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    
    if not user or not pwd_context.verify(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Email hoặc mật khẩu không chính xác!"
        })
    
    request.session.clear() 

    if user.role in ["admin", UserRole.ADMIN]:
        # ADMIN: Đi qua bước verify
        request.session["pending_admin_id"] = user.id
        return RedirectResponse(url="/admin/verify", status_code=status.HTTP_303_SEE_OTHER)
    else:
        # MEMBER: Vào thẳng Workspace
        request.session["user_id"] = user.id
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
async def register_action(
    request: Request, 
    email: str = Form(...), 
    password: str = Form(...), 
    full_name: str = Form(...), 
    org_name: str = Form(...), 
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email đã tồn tại!"})
        
    org = db.query(Organization).filter(Organization.name == org_name).first()
    if not org:
        org = Organization(name=org_name)
        db.add(org)
        db.commit()
        db.refresh(org)
        
    hashed_pwd = pwd_context.hash(password)
    new_user = User(
        email=email, 
        hashed_password=hashed_pwd, 
        full_name=full_name, 
        org_id=org.id,
        role=UserRole.MEMBER 
    )
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/logout")
async def logout_action(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 3. BƯỚC NHẢY XÁC THỰC CHO ADMIN (2FA)
# ==========================================
@router.get("/admin/verify", response_class=HTMLResponse)
async def admin_verify_page(request: Request, db: Session = Depends(get_db)):
    """Trang nhập mã bảo mật cho Admin"""
    pending_id = request.session.get("pending_admin_id")
    if not pending_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    user = db.query(User).filter(User.id == pending_id).first()
    return templates.TemplateResponse("admin_verify.html", {
        "request": request, 
        "user": user 
    })

@router.post("/admin/verify")
async def admin_verify_action(
    request: Request, 
    security_code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Xử lý mã xác thực"""
    pending_id = request.session.get("pending_admin_id")
    if not pending_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    EXPECTED_CODE = os.getenv("ADMIN_SECURITY_CODE", "GUARDPRO_2026")

    if security_code != EXPECTED_CODE:
        user = db.query(User).filter(User.id == pending_id).first()
        return templates.TemplateResponse("admin_verify.html", {
            "request": request, 
            "user": user,
            "error": "Mã xác thực không hợp lệ!"
        })

    # XÁC THỰC THÀNH CÔNG: Chuyển từ phiên chờ sang phiên chính thức
    request.session.pop("pending_admin_id", None)
    request.session["user_id"] = pending_id
    
    # [FIX QUAN TRỌNG]: Đẩy về /admin/users chứ không phải /admin/verify
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 4. QUẢN TRỊ VIÊN: TRANG QUẢN LÝ NHÂN SỰ
# ==========================================
@router.get("/admin/users", response_class=HTMLResponse) # [FIX]: Đổi đường dẫn thành /admin/users
async def admin_users_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: 
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        
    current_user = db.query(User).filter(User.id == user_id).first()
    
    # Kiểm tra quyền Admin thực sự (sau khi đã qua 2FA)
    if not current_user or current_user.role not in ["admin", UserRole.ADMIN]:
        return RedirectResponse(url="/management")

    # Lấy danh sách toàn bộ người dùng khác để phân quyền
    users_list = db.query(User).filter(User.id != current_user.id).order_by(User.id.desc()).all()

    return templates.TemplateResponse("admin_users.html", { # [FIX]: Gọi đúng file admin_users.html
        "request": request,
        "user": current_user,  
        "users": users_list    
    })

# --- HÀM CẤP QUYỀN (PROMOTE) ---
@router.post("/admin/promote/{target_user_id}")
async def promote_to_admin(target_user_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == user_id).first()
    
    # Kiểm tra quyền Admin của người thực hiện
    if not current_user or current_user.role not in ["admin", UserRole.ADMIN]:
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        return HTMLResponse("<script>alert('Không tìm thấy người dùng.'); window.history.back();</script>")

    target_user.role = UserRole.ADMIN
    db.commit()
    
    # Sau khi xử lý xong, quay lại trang danh sách nhân sự
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


# --- HÀM GỠ QUYỀN (DEMOTE) ---
# Chuyển từ .put sang .post và khớp đường dẫn /admin/demote/
@router.post("/admin/demote/{target_user_id}")
async def revoke_admin_privileges(target_user_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == user_id).first()
    
    if not current_user or current_user.role not in ["admin", UserRole.ADMIN]:
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

    # Bảo vệ: Không cho phép tự hạ quyền chính mình
    if user_id == target_user_id:
        return HTMLResponse("<script>alert('Bạn không thể tự hạ quyền của chính mình.'); window.history.back();</script>")

    target_user = db.query(User).filter(User.id == target_user_id).first()
    
    # Bảo vệ: Không cho phép hạ quyền tài khoản Admin hệ thống gốc
    if target_user and target_user.email == "admin@system.local":
        return HTMLResponse("<script>alert('Không thể hạ quyền tài khoản quản trị gốc của hệ thống!'); window.history.back();</script>")

    if target_user:
        target_user.role = UserRole.MEMBER
        db.commit()
    
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)
# ==========================================
# 5. WORKSPACE & QUẢN LÝ DỰ ÁN
# ==========================================
@router.get("/management", response_class=HTMLResponse)
async def management_page(request: Request, db: Session = Depends(get_db)):
    # 1. Kiểm tra ID trong session
    user_id = request.session.get("user_id")
    if not user_id: 
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # 2. Truy vấn User từ DB
    current_user = db.query(User).filter(User.id == user_id).first()
    
    # FIX LỖI: Nếu ID có trong session nhưng không tìm thấy User trong DB (NoneType)
    if not current_user:
        request.session.clear() # Xóa session lỗi để tránh vòng lặp redirect
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    # 3. Lấy danh sách dự án dựa trên quyền
    # Kiểm tra cả giá trị string và Enum để đảm bảo tính tương thích
    is_admin = current_user.role == "admin" or current_user.role == UserRole.ADMIN

    if is_admin:
        # 1. Admin thấy toàn bộ dự án
        projects = db.query(Project).filter(Project.is_deleted == False).all()
        
        # 2. CHỈNH SỬA: Lấy tất cả thành viên trong tổ chức, bao gồm cả chính mình
        members = db.query(User).filter(
            User.org_id == current_user.org_id  # Chỉ lấy người cùng công ty/tổ chức
        ).all()
    else:
        # Member thì giữ nguyên logic cũ
        projects = db.query(Project).filter(
            (Project.owner_id == current_user.id) | (Project.creator_id == current_user.id),
            Project.is_deleted == False
        ).all()
        members = []

    return templates.TemplateResponse("management.html", {
        "request": request, 
        "user": current_user, 
        "projects": projects,
        "members": members
    })


# security_gate/api/ui_routes.py

@router.post("/create_project")
async def create_project(
    request: Request, 
    project_name: str = Form(...), 
    assignee_id: Optional[str] = Form(None), # Nhận dạng str để tránh lỗi 422 khi gửi chuỗi rỗng
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == user_id).first()
    
    if not current_user:
        return RedirectResponse(url="/login")

    # Mặc định người phụ trách là người tạo
    owner_id = current_user.id
    
    # LOGIC PHÂN CHIA DỰ ÁN
    # Kiểm tra: Phải là Admin VÀ có chọn nhân viên (assignee_id không rỗng)
    if current_user.role in ["admin", "UserRole.ADMIN"] and assignee_id and assignee_id.strip():
        try:
            owner_id = int(assignee_id)
        except ValueError:
            owner_id = current_user.id # Nếu lỗi convert thì mặc định là admin

    new_proj = Project(
        name=project_name, 
        description="Dự án đánh giá ASVS 5.0", 
        organization_id=current_user.org_id, 
        owner_id=owner_id,      # ID người phụ trách (Nhân viên được giao)
        creator_id=current_user.id, # ID người tạo (Admin)
        is_locked=False,
        is_deleted=False
    )
    
    try:
        db.add(new_proj)
        db.commit()
        db.refresh(new_proj)
        print(f"✅ Đã tạo dự án '{project_name}' - Giao cho User ID: {owner_id}")
    except Exception as e:
        db.rollback()
        print(f"❌ Lỗi Database: {e}")
    
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/project/{project_id}/toggle_lock")
async def toggle_lock_project(request: Request, project_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    
    if user.role not in ["admin", UserRole.ADMIN]:
        return HTMLResponse("🚫 403: Cần quyền Admin.", status_code=403)

    project = db.query(Project).filter(Project.id == project_id, Project.organization_id == user.org_id).first()
    if project:
        project.is_locked = not project.is_locked
        db.commit()
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/delete_project/{project_id}")
async def delete_project(request: Request, project_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    
    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    if not project:
        return HTMLResponse("<h2 style='color:red;'>Dự án không tồn tại.</h2>", status_code=404)
        
    if project.creator_id != user.id:
        return HTMLResponse("<h2 style='color:red;'>🚫 403: Chỉ người tạo ra dự án mới có quyền xóa.</h2>", status_code=403)
    
    project.is_deleted = True
    db.commit()
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 6. LÕI: GIAO DIỆN QUÉT MÃ & LỊCH SỬ
# ==========================================
@router.get("/project/{project_id}", response_class=HTMLResponse)
async def project_scan_page(request: Request, project_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: return RedirectResponse(url="/login")
    
    user = db.query(User).filter(User.id == user_id).first()
    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    
    if not project: return RedirectResponse(url="/management")

    # Vá lỗi IDOR (TC-05)
    if user.role in ["admin", UserRole.ADMIN]:
        if project.organization_id != user.org_id: return RedirectResponse(url="/management")
    else:
        if project.owner_id != user.id and project.creator_id != user.id: return RedirectResponse(url="/management")
        
    return templates.TemplateResponse("index.html", {
        "request": request, "user": user, "project": project
    })

@router.get("/project/{project_id}/history", response_class=HTMLResponse)
async def project_history_page(request: Request, project_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: return RedirectResponse(url="/login")
    
    user = db.query(User).filter(User.id == user_id).first()
    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    
    if not project: return RedirectResponse(url="/management")

    # Vá lỗi IDOR (TC-05)
    if user.role in ["admin", UserRole.ADMIN]:
        if project.organization_id != user.org_id: return RedirectResponse(url="/management")
    else:
        if project.owner_id != user.id and project.creator_id != user.id: return RedirectResponse(url="/management")
            
    scan_history = db.query(ScanReport).filter(
        ScanReport.project_id == project_id, 
        ScanReport.is_deleted == False
    ).order_by(ScanReport.scan_date.desc()).all()
    
    return templates.TemplateResponse("history.html", {
        "request": request, "project": project, "scan_history": scan_history, "user": user
    })

@router.post("/delete_report/{report_id}")
async def delete_report(request: Request, report_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: return RedirectResponse(url="/login")
    
    user = db.query(User).filter(User.id == user_id).first()
    report = db.query(ScanReport).join(Project).filter(
        ScanReport.id == report_id, ScanReport.is_deleted == False
    ).first()
    
    if report:
        project = db.query(Project).filter(Project.id == report.project_id).first()
        if user.role not in ["admin", UserRole.ADMIN] and project.owner_id != user.id:
             return HTMLResponse("Không đủ quyền xóa báo cáo này.", status_code=403)
             
        report.is_deleted = True
        db.commit()
        return RedirectResponse(url=f"/project/{project.id}/history", status_code=status.HTTP_303_SEE_OTHER)
        
    return HTMLResponse("Không tìm thấy báo cáo", status_code=404)

# ==========================================
# 7. QUẢN LÝ DỰ ÁN (NÂNG CẤP QUYỀN KHÓA/XÓA)
# ==========================================

@router.post("/project/{project_id}/toggle_lock")
async def toggle_lock_project(request: Request, project_id: int, db: Session = Depends(get_db)):
    """CHỈ QUẢN TRỊ VIÊN mới có quyền Khóa/Mở dự án"""
    user_id = request.session.get("user_id")
    # Luôn lấy lại thông tin user từ DB để đảm bảo Role là mới nhất
    current_user = db.query(User).filter(User.id == user_id).first()
    
    # 1. Kiểm tra nếu không phải Admin thì chặn ngay lập tức
    if not current_user or current_user.role not in ["admin", UserRole.ADMIN]:
        return RedirectResponse(url="/management", status_code=status.HTTP_403_FORBIDDEN)

    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    if project:
        project.is_locked = not project.is_locked
        db.commit()
    
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/delete_project/{project_id}")
async def delete_project(request: Request, project_id: int, db: Session = Depends(get_db)):
    """CHỈ người tạo dự án (Creator) mới có quyền xóa"""
    user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == user_id).first()
    
    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    if not project:
        return JSONResponse(status_code=404, content={"error": "Dự án không tồn tại."})
        
    # LOGIC NGHIÊM NGẶT: Admin cũng không được xóa nếu không phải người tạo
    if project.creator_id != current_user.id:
        return HTMLResponse(
            content="<script>alert('🚫 CHỈ NGƯỜI TẠO DỰ ÁN MỚI CÓ QUYỀN XÓA. Admin chỉ được phép khóa dự án này.'); window.location.href='/management';</script>",
            status_code=403
        )
    
    project.is_deleted = True
    db.commit()
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/project/{project_id}/reassign")
async def reassign_project(
    project_id: int, 
    request: Request, 
    new_owner_id: int = Form(...), 
    db: Session = Depends(get_db)
):
    """Admin thay đổi người phụ trách cho các dự án do Admin tạo"""
    user_id = request.session.get("user_id")
    current_user = db.query(User).filter(User.id == user_id).first()
    
    if not current_user or current_user.role not in ["admin", UserRole.ADMIN]:
        return JSONResponse(status_code=403, content={"error": "Bạn không có quyền quản trị."})

    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    if not project:
        return JSONResponse(status_code=404, content={"error": "Dự án không tồn tại."})

    # [LOGIC QUAN TRỌNG]: Admin chỉ được phân chia lại dự án mà người tạo là Admin
    # Lấy thông tin người tạo dự án
    creator = db.query(User).filter(User.id == project.creator_id).first()
    
    if creator.role not in ["admin", UserRole.ADMIN]:
        return HTMLResponse(
            content="<script>alert('🚫 KHÔNG THỂ PHÂN CHIA: Đây là dự án cá nhân do Member tạo ra.'); window.location.href='/management';</script>",
            status_code=403
        )

    # Thực hiện thay đổi người phụ trách
    project.owner_id = new_owner_id
    db.commit()
    
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)