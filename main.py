from fastapi import FastAPI, Depends, Request, Form, HTTPException, Cookie
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from fastapi.staticfiles import StaticFiles
from typing import Optional

from .database import Base, engine, SessionLocal
from .models import User
from .auth import *

app = FastAPI()
app.mount("/static", StaticFiles(directory="projectt/static"), name="static")
Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="projectt/templates")

OFFERS = {
    1: {"id": 1, "title": "Париж", "description": "Місто кохання", "image": "paris.jpg"},
    2: {"id": 2, "title": "Токіо", "description": "Технології та традиції", "image": "tokyo.jpg"},
    3: {"id": 3, "title": "Нью-Йорк", "description": "Місто можливостей", "image": "newyork.jpg"},
    4: {"id": 4, "title": "Рим", "description": "Історія на кожному кроці", "image": "rome.jpg"},
}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    token: str | None = Cookie(default=None),
    db: Session = Depends(get_db)
):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = decode_token(token)
        user = db.query(User).filter(User.username == payload["sub"]).first()

        if not user or user.is_blocked:
            raise HTTPException(status_code=403)

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    
def get_current_user_optional(
    token: Optional[str] = Cookie(default=None),
    db: Session = Depends(get_db)
) -> Optional[User]:

    if token is None:
        return None

    try:
        payload = decode_token(token)

        username = payload.get("sub")
        if not username:
            return None

        user = db.query(User).filter(User.username == username).first()

        if not user or user.is_blocked:
            return None

        return user

    except JWTError:
        return None
    
@app.get("/offer/{offer_id}")
def offer_page(
    offer_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_optional)
):
    if not user:
        return RedirectResponse("/login", status_code=302)

    offer = OFFERS[offer_id]
    return templates.TemplateResponse(
        "offer.html",
        {"request": request, "offer": offer, "user": user}
    )

@app.get("/")
def index(
    request: Request,
    user: User | None = Depends(get_current_user_optional)
):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "offers": OFFERS.values()
        }
    )



@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register(username: str = Form(), password: str = Form(), db: Session = Depends(get_db)):
    is_first_user = db.query(User).count() == 0

    user = User(
        username=username,
        password=hash_password(password),
        is_admin=is_first_user
    )

    db.add(user)
    db.commit()
    return RedirectResponse("/login", status_code=302)


@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(
    username: str = Form(),
    password: str = Form(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.is_blocked:
        raise HTTPException(status_code=403, detail="User is blocked")

    token = create_access_token(user.username)

    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        key="token",
        value=token,
        httponly=True
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("token")
    return response

@app.get("/admin")
def admin_panel(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user)
):
    if not admin.is_admin:
        raise HTTPException(status_code=403)

    users = db.query(User).all()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "users": users,
            "user": admin
        }
    )



@app.post("/admin/block/{user_id}")
def block_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user)
):
    if not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admins only")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot block yourself")

    user.is_blocked = not user.is_blocked
    db.commit()

    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/make_admin/{user_id}")
def toggle_admin_cookie(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Тільки адміністратор може змінювати права")

    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Неможливо змінити власні права")

    user.is_admin = not user.is_admin
    db.commit()
    
    return RedirectResponse("/admin", status_code=302)

