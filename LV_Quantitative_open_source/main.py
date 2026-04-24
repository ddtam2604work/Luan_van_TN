import uvicorn
import logging
import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from passlib.context import CryptContext

# Import Database Config & Models
from security_gate.database.session import engine, Base, SessionLocal
from security_gate.database.models import User, UserRole, Organization

# Import Routers
from security_gate.api.routes import router as api_router
from security_gate.api.ui_routes import router as ui_router

# ==========================================
# CẤU HÌNH LOGGING
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==========================================
# 1. MIDDLEWARE BẢO VỆ SERVER (Giới hạn Upload 5GB)
# ==========================================
class LimitUploadSizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_upload_size: int):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            content_length = request.headers.get('content-length')
            if content_length and int(content_length) > self.max_upload_size:
                raise HTTPException(status_code=413, detail="File quá lớn. Giới hạn upload là 5GB.")
        return await call_next(request)

# ==========================================
# 2. LIFESPAN: QUẢN LÝ VÒNG ĐỜI & AUTO-SEED ADMIN
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- LOGIC KHỞI ĐỘNG (STARTUP) ---
    logger.info("🚀 Supply Chain Guard Pro Engine đang khởi động...")
    
    # A. Khởi tạo các thư mục thiết yếu
    for path in ["data/uploads", "data/sbom", "data/reports", "security_gate/static"]:
        Path(path).mkdir(parents=True, exist_ok=True)
        
    # B. Tạo bảng trong CSDL
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database đã được đồng bộ.")
    
    # C. [TÍNH NĂNG CHÍNH]: TỰ ĐỘNG TẠO ADMIN KHI CHƯA CÓ
    db = SessionLocal()
    try:
        # Kiểm tra nếu chưa có bất kỳ Admin nào trong hệ thống
        if not db.query(User).filter(User.role == UserRole.ADMIN).first():
            logger.info("🔍 Chưa tìm thấy Admin. Đang tiến hành khởi tạo...")
            
            # 1. Tạo tổ chức mặc định
            org = db.query(Organization).filter(Organization.name == "Headquarters").first()
            if not org:
                org = Organization(name="Headquarters")
                db.add(org)
                db.commit()
                db.refresh(org)
            
            # 2. Lấy thông tin Admin từ biến môi trường (hoặc dùng mặc định)
            admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@system.local")
            admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Secret123!")
            
            new_admin = User(
                email=admin_email,
                hashed_password=pwd_context.hash(admin_password),
                full_name="Root Admin",
                role=UserRole.ADMIN,
                org_id=org.id
            )
            db.add(new_admin)
            db.commit()
            logger.info(f"✨ TẠO TÀI KHOẢN ADMIN THÀNH CÔNG: {admin_email}")
            logger.info(f"🔑 Mật khẩu mặc định: {admin_password}")
        else:
            logger.info("ℹ️ Tài khoản Admin đã tồn tại, bỏ qua bước khởi tạo.")
    except Exception as e:
        logger.error(f"❌ Lỗi khi khởi tạo Admin: {e}")
        db.rollback()
    finally:
        db.close()
    
    logger.info("✅ Các thư mục dữ liệu đã sẵn sàng.")
    
    yield # Chạy Server
    
    # --- LOGIC TẮT SERVER (SHUTDOWN) ---
    logger.info("🛑 Đang tắt hệ thống Guard Pro an toàn...")

# ==========================================
# 3. KHỞI TẠO HỆ THỐNG APP
# ==========================================
app = FastAPI(
    title="Supply Chain Guard Pro API", 
    description="Engine định lượng rủi ro chuỗi cung ứng phần mềm (chuẩn OWASP ASVS 5.0.0)", 
    version="1.0.0",
    lifespan=lifespan
)

# ==========================================
# 4. CẤU HÌNH MIDDLEWARE
# ==========================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware, 
    secret_key="luan_van_super_secret_key_2026",
    session_cookie="guardpro_session", 
    max_age=86400,          
    same_site="lax",        
    https_only=False        
)

app.add_middleware(LimitUploadSizeMiddleware, max_upload_size=5368709120)

# ==========================================
# 5. GẮN STATIC FILES VÀ ROUTERS
# ==========================================
app.mount("/static", StaticFiles(directory="security_gate/static"), name="static")

app.include_router(ui_router) 
app.include_router(api_router)

# ==========================================
# 6. GLOBAL EXCEPTION HANDLERS
# ==========================================
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"detail": "API endpoint không tồn tại."})
    return HTMLResponse(
        status_code=404, 
        content="<div style='text-align:center; padding-top:100px; font-family:sans-serif;'><h1>404</h1><h2>Trang không tồn tại</h2><a href='/'>Quay về trang chủ</a></div>"
    )

@app.exception_handler(500)
async def custom_500_handler(request: Request, exc: Exception):
    logger.error(f"Lỗi Server (500) tại {request.url.path}: {str(exc)}")
    return HTMLResponse(
        status_code=500, 
        content="<div style='text-align:center; padding-top:100px; font-family:sans-serif;'><h1>500</h1><h2>Hệ thống đang gặp sự cố</h2><p>Vui lòng thử lại sau hoặc liên hệ Admin.</p><a href='/'>Quay về trang chủ</a></div>"
    )

# ==========================================
# 7. ENTRY POINT KHỞI CHẠY SERVER
# ==========================================
if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="127.0.0.1",  
        port=8000, 
        reload=True,
        timeout_keep_alive=600 
    )