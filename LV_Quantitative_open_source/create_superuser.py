from sqlalchemy.orm import Session
from passlib.context import CryptContext
from security_gate.database.session import SessionLocal
from security_gate.database.models import User, Organization, UserRole

# Khởi tạo công cụ băm mật khẩu
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_first_admin():
    db: Session = SessionLocal()
    try:
        # Kiểm tra xem đã có admin nào chưa
        admin_exists = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if admin_exists:
            print("⚠️ Hệ thống đã có tài khoản Admin. Bỏ qua bước khởi tạo.")
            return

        print("🚀 Bắt đầu khởi tạo tài khoản Root Admin...")
        
        # 1. Tạo một Tổ chức/Tenant mặc định (nếu hệ thống của bạn yêu cầu org_id)
        default_org = db.query(Organization).filter(Organization.name == "System Admin").first()
        if not default_org:
            default_org = Organization(name="System Admin")
            db.add(default_org)
            db.commit()
            db.refresh(default_org)

        # 2. Tạo tài khoản Admin
        email = "admin@guardpro.com"
        password = "AdminPassword@2026!" # Trong thực tế nên dùng input() để nhập ẩn
        hashed_pwd = pwd_context.hash(password)

        root_admin = User(
            email=email,
            hashed_password=hashed_pwd,
            full_name="System Administrator",
            role=UserRole.ADMIN,
            org_id=default_org.id
        )
        
        db.add(root_admin)
        db.commit()
        print(f"✅ Đã tạo thành công Root Admin!")
        print(f"📧 Email: {email}")
        print(f"🔑 Mật khẩu: {password}")

    except Exception as e:
        db.rollback()
        print(f"❌ Lỗi khởi tạo: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_first_admin()