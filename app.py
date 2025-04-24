from __future__ import annotations
import os, time, random, functools, logging, click
from typing import Callable, Any, Iterable
import validators

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, current_user, login_required
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

# Flask & DB 基本設定
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI="sqlite:///restaurants.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-key"),
)
db = SQLAlchemy(app)

# LoginManager
login_manager = LoginManager(app)
login_manager.login_view = "login"

# 日誌設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)


# 共用工具：時間紀錄 / Assert
def timed_view(func: Callable):
    """量測 view 執行時間並統一例外處理"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        except Exception as err:
            logging.exception("View %s raised → %s", func.__name__, err)
            raise
        finally:
            ms = (time.perf_counter() - start) * 1_000
            logging.info("⏱  %s finished in %.2f ms", func.__name__, ms)
    return wrapper


def _check_price(price: str):
    assert price in {"$", "$$", "$$$"}, "價位必須是 $, $$ 或 $$$"

def _check_website(url: str):
    assert validators.url(url), "網站格式錯誤"

VALID_LOCATIONS = ["中壢市區", "平鎮市區", "宵夜街", "奢侈巷", "後門", "其他"]
def _check_location(loc: str):
    assert loc in VALID_LOCATIONS, "位置不合法"


# 資料物件：Base / User / Restaurant
class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)

    @classmethod
    def get(cls, rid: int):
        return cls.query.get_or_404(rid)

    @classmethod
    def distinct_column(cls, field: str):
        assert hasattr(cls, field), f"欄位 {field} 不存在"
        column = getattr(cls, field)
        return db.session.scalars(db.select(column).distinct()).all()


# 多對多收藏表
favorites = db.Table(
    "favorites",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id")),
    db.Column("restaurant_id", db.Integer, db.ForeignKey("restaurants.id")),
)


class User(BaseModel, UserMixin):
    __tablename__ = "users"

    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role     = db.Column(db.String(8), default="user")  # 'user' or 'admin' or 'contributor'
    contributor_pending = db.Column(db.Boolean, default=False)

    favorites = db.relationship(
        "Restaurant", secondary=favorites, lazy="dynamic",
        backref=db.backref("fans", lazy="dynamic")
    )

    # 密碼雜湊
    def set_password(self, raw: str):
        self.password = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password, raw)


class Restaurant(BaseModel):
    __tablename__ = "restaurants"

    name        = db.Column(db.String(64),  nullable=False)
    category    = db.Column(db.String(32),  nullable=False)
    price_range = db.Column(db.String(16),  nullable=False)
    location     = db.Column(db.String(128), nullable=False)
    website     = db.Column(db.String(256))

    def __repr__(self) -> str:
        return f"<{self.id}: {self.name} ({self.category})>"

    def to_dict(self) -> dict:
        return dict(
            id=self.id, name=self.name, category=self.category,
            price=self.price_range, location=self.location,
            website=self.website
        )


# Flask‑Login 回呼
@login_manager.user_loader
def load_user(uid: str):
    return User.get(int(uid))


# 權限裝飾器
def admin_required(func: Callable) -> Callable:
    @functools.wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            flash("需要管理員權限")
            return redirect(url_for("index"))
        return func(*args, **kwargs)
    return wrapper

def contributor_or_admin_required(func):
    @functools.wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role not in ("admin", "contributor"):
            flash("僅限協作者或管理員")
            return redirect(url_for("index"))
        return func(*args, **kwargs)
    return wrapper


# Service 層（封裝 DB 操作）               
class RestaurantService:
    def __init__(self, session):
        self.session = session

    # 新增、編輯、刪除餐廳資料
    def add(self, **data):
        _check_price(data["price_range"])
        _check_location(data["location"])
        if data["website"] != None:
            _check_website(data["website"])
        self.session.add(Restaurant(**data))
        self.session.commit()

    def update(self, target: Restaurant, **data):
        _check_price(data["price_range"])
        _check_location(data["location"])
        if data["website"] != None:
            _check_website(data["website"])
        for k, v in data.items():
            setattr(target, k, v)
        self.session.commit()

    def delete(self, target: Restaurant):
        self.session.delete(target)
        self.session.commit()

    # 隨機選擇餐廳 or 得到餐廳列表
    def random_pick(self, action: str, category=None, price=None, location=None) -> Restaurant | None:
        query = Restaurant.query
        if category: query = query.filter_by(category=category)
        if price:    query = query.filter_by(price_range=price)
        if location: query = query.filter_by(location=location)
        pool = query.all()
        if action == "random":
            choice = [random.choice(pool)] if pool else None
            return choice
        elif action == "list":
            return pool if pool else None
        else:
            raise ValueError("action must be 'random' or 'list'") #raise error


service = RestaurantService(db.session)


# CLI 指令                                 
@app.cli.command("init-db")
def init_db():
    """初始化資料庫"""
    db.create_all()
    print("✓ database created")

@app.cli.command("create-admin")
@click.argument("username")
@click.argument("password")
def create_admin(username, password):
    """快速建立管理員帳號"""
    if User.query.filter_by(username=username).first():
        print("⚠  帳號已存在")
        return
    user = User(username=username, role="admin")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print("✓ admin created")


# Public Routes              
@app.route("/", methods=["GET", "POST"])
@timed_view
def index():
    categories = Restaurant.distinct_column("category")
    prices = Restaurant.distinct_column("price_range")
    locations = Restaurant.distinct_column("location")

    if request.method == "POST":
        category = request.form.get("category") or None
        price    = request.form.get("price") or None
        location = request.form.get("location") or None
        action = request.form.get("action")
        choices   = service.random_pick(action, category, price, location)
        if not choices:
            flash("沒有符合條件的餐廳 😢")
            return redirect(url_for("index"))
        return render_template("index.html", 
                               choices=choices,categories=categories, prices=prices, locations=locations)

    return render_template("index.html",
                           categories=categories, prices=prices, locations=locations)

@app.route("/api/random")
@timed_view
def api_random():
    r = service.random_pick(action="random")
    return (jsonify(r.to_dict()) if r
            else (jsonify(error="empty"), 404))


# Auth Routes                               
@app.route("/register", methods=["GET", "POST"])
@timed_view
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            flash("帳號已存在")
            return redirect(url_for("register"))
        user = User(username=username)               # role 預設 'user'
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("✓ 註冊成功，請登入")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@timed_view
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("✓ 登入成功")
            next_page = request.args.get("next") or url_for("index")
            return redirect(next_page)
        flash("帳號或密碼錯誤")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("已登出")
    return redirect(url_for("index"))


# 收藏功能
@app.route("/favorite/<int:rid>", methods=["POST"])
@login_required
@timed_view
def toggle_favorite(rid):
    rest = Restaurant.get(rid)
    if current_user.favorites.filter(favorites.c.restaurant_id == rid).first():
        current_user.favorites.remove(rest)
        flash("已取消收藏")
    else:
        current_user.favorites.append(rest)
        flash("已加入收藏")
    db.session.commit()
    return redirect(request.referrer or url_for("index"))

@app.route("/my_favorites")
@login_required
@timed_view
def my_favorites():
    favs = current_user.favorites.order_by(Restaurant.id).all()
    return render_template("my_favorites.html", stores=favs)


# 協作者功能                         
@app.route("/apply", methods=["POST"])
@login_required
def apply_contributor():
    if current_user.role != "user":
        flash("你已是協作者或管理員")
    else:
        current_user.contributor_pending = True
        db.session.commit()
        flash("申請已送出，請等待管理員審核")
    return redirect(url_for("index"))

@app.route("/add", methods=["GET", "POST"])
@app.route("/edit/<int:rid>", methods=["GET", "POST"])
@contributor_or_admin_required
@timed_view
def add_edit(rid: int | None = None):
    target = Restaurant.get(rid) if rid else None
    if request.method == "POST":
        form = dict(
            name=request.form["name"],
            category=request.form["category"],
            price_range=request.form["price_range"],
            location=request.form["location"],
            website=request.form["website"] or None,
        )
        if target:
            service.update(target, **form)
            flash("✓ 已更新餐廳")
        else:
            service.add(**form)
            flash("✓ 已新增餐廳")
        return redirect(url_for("list_restaurants"))
    return render_template("add_edit.html", store=target)


# 管理員專屬 Routes                         
@app.route("/restaurants")
@admin_required
@timed_view
def list_restaurants():
    stores = Restaurant.query.order_by(Restaurant.id).all()
    return render_template("list.html", stores=stores)

@app.route("/delete/<int:rid>", methods=["POST"])
@admin_required
@timed_view
def delete(rid: int):
    service.delete(Restaurant.get(rid))
    flash("✓ 已刪除")
    return redirect(url_for("list_restaurants"))

@app.route("/approve_requests")
@admin_required
@timed_view
def approve_requests():
    pending = User.query.filter_by(contributor_pending=True).all()
    return render_template("approve_requests.html", users=pending)

@app.route("/approve/<int:uid>", methods=["POST"])
@admin_required
@timed_view
def approve(uid):
    u = User.get(uid)
    u.role = "contributor"
    u.contributor_pending = False
    db.session.commit()
    flash(f"✓ {u.username} 已成為協作者")
    return redirect(url_for("approve_requests"))

@app.route("/reject/<int:uid>", methods=["POST"])
@admin_required
@timed_view
def reject(uid):
    u = User.get(uid)
    u.contributor_pending = False
    db.session.commit()
    flash(f"✖️ {u.username} 的協作者申請已被拒絕")
    return redirect(url_for("approve_requests"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    with app.app_context():
        db.create_all()
    app.run(debug=False, host="0.0.0.0", port=port)