from flask import Flask, render_template, request, redirect, url_for, flash, session
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import datetime 
import smtplib
from email.message import EmailMessage
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret-change-me")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


@app.context_processor
def inject_user():
    return dict(user=session.get("user"))

#simple email function to send emails using SMTP
def send_email(to, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("SMTP_USER")
    msg["To"] = to
    msg.set_content(body)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
        server.send_message(msg)

# to authenticate routes
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            flash("Please log in first.", "warn")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user or not user.get("is_admin"):
            flash("You do not have permission to access this page.", "err")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


#auth route 
# modified to send welcome email upon signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        role = "Diner"
        phone = request.form["phone"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        full_name = request.form["full_name"].strip()

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "err")
            return redirect(url_for("signup"))

        existing = supabase.table("users").select("email").eq("email", email).execute()
        if existing.data:
            flash("Email already registered.", "warn")
            return redirect(url_for("signup"))

        hashed = generate_password_hash(password)
        supabase.table("users").insert({
            "role": role,
            "email": email,
            "password_hash": hashed,
            "full_name": full_name,
            "is_admin": 0
        }).execute()
        send_email(email, "TableTime - Welcome!", "Welcome to TableTime! We're excited to have you on board.")
        flash("Account created! Please log in.", "ok")
        return redirect(url_for("login"))
    return render_template("signup.html", title="Sign Up")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        res = supabase.table("users").select("*").eq("email", email).limit(1).execute()
        if not res.data:
            flash("User not found.", "err")
            return redirect(url_for("login"))
        user = res.data[0]
        if not check_password_hash(user["password_hash"], password):
            flash("Incorrect password.", "err")
            return redirect(url_for("login"))
        session["user"] = {
            "id": user["user_id"],
            "email": user["email"],
            "name": user.get("full_name"),
            "role": user["role"],
            "is_admin": user.get("is_admin", 0)
        }
        flash("Logged in!", "ok")
        return redirect(url_for("dashboard"))
    return render_template("login.html", title="Login")


@app.get("/logout")
def logout():
    session.clear()
    flash("Logged out.", "warn")
    return redirect(url_for("login"))


# ----------------------------main routes
@app.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"], title="Dashboard")


@app.get("/")
@login_required
def index():
    user = session.get("user")
    res = supabase.table("reservations").select("*").order("reservation_id").execute()
    restaurants = supabase.table("restaurants").select("*").order("restaurant_id").execute()
    tables = supabase.table("tables").select("*").execute()
    return render_template("reservations.html", user=user, tables=tables.data, reservations=res.data, restaurants=restaurants.data, title="Reservations")



#profile route
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session.get("user", {}).get("id")
    res = supabase.table("users").select("*").eq("user_id", user_id).limit(1).execute()
    user = res.data[0] if res.data else {}

    if request.method == "POST":
        updates = {
            "full_name": request.form.get("full_name"),
            "email": request.form.get("email"),
            "phone": request.form.get("phone")
        }
        supabase.table("users").update(updates).eq("user_id", user_id).execute()
        session["user"].update(updates)
        flash("Profile updated successfully!", "success")
        return redirect("/profile")

    return render_template("profile.html", user=user, title="Profile")



@app.post("/reservations/add")
@login_required
def add_reservation():
    payload = {
        "user_id": int(session["user"]["id"]),
        "restaurant_id": int(request.form["restaurant_id"]),
        "table_id": int(request.form["table_id"]),
        "party_size": int(request.form["party_size"]),
        "reservation_time": request.form["reservation_time"],
        "status": "Pending"
    }
    out = supabase.table("reservations").insert(payload).execute()
    #add to notifications
    
    flash("Reservation created" if out.data else "Failed to create reservation", "ok" if out.data else "err")
    return redirect(url_for("index"))


@app.post("/reservations/delete")
@login_required
def delete_reservation():
    rid = request.form.get("reservation_id")
    user = session.get("user")
    # Only allow delete if admin or owner
    res = supabase.table("reservations").select("user_id").eq("reservation_id", rid).execute()
    if not res.data:
        flash("Reservation not found.", "err")
    elif user["is_admin"] or res.data[0]["user_id"] == user["id"]:
        supabase.table("reservations").delete().eq("reservation_id", rid).execute()
        flash(f"Reservation {rid} deleted", "warn")

    else:
        flash("You are not allowed to delete this reservation.", "err")
    return redirect(url_for("index"))


#admin routes for managing entities
@app.route("/restaurants", methods=["GET", "POST"])
@login_required
@admin_required
def restaurants():
    if request.method == "POST":
        if "__delete_id" in request.form:
            supabase.table("restaurants").delete().eq("restaurant_id", request.form["__delete_id"]).execute()
            flash("Restaurant deleted", "warn")
        else:
            payload = {
                "name": request.form["name"],
                "address": request.form["address"],
                "phone": request.form["phone"],
                "email": request.form["email"],
                "open_time": request.form["open_time"],
                "close_time": request.form["close_time"]
            }
            supabase.table("restaurants").insert(payload).execute()
            flash("Restaurant created", "ok")
    data = supabase.table("restaurants").select("*").order("restaurant_id").execute()
    return render_template("restaurants.html", items=data.data, title="Restaurants")


@app.route("/tables", methods=["GET", "POST"])
@login_required
@admin_required
def tables_view():
    if request.method == "POST":
        if "__delete_id" in request.form:
            supabase.table("tables").delete().eq("table_id", request.form["__delete_id"]).execute()
            flash("Table deleted", "warn")
        else:
            payload = {
                "restaurant_id": int(request.form["restaurant_id"]),
                "table_number": request.form["table_number"],
                "capacity": int(request.form["capacity"]),
                "status": request.form["status"]
            }
            supabase.table("tables").insert(payload).execute()
            flash("Table created", "ok")
    data = supabase.table("tables").select("*").order("table_id").execute()
    restaurants = supabase.table("restaurants").select("*").order("restaurant_id").execute()
    
    return render_template("tables.html", items=data.data,restaurants=restaurants.data, title="Tables")


@app.route("/menu", methods=["GET", "POST"])
@login_required
@admin_required
def menu_items():
    if request.method == "POST":
        if "__delete_id" in request.form:
            supabase.table("menu_items").delete().eq("item_id", request.form["__delete_id"]).execute()
            flash("Menu item deleted", "warn")
        else:
            is_available = str(request.form.get("is_available", "true")).lower() in ["true", "1", "yes", "y", "on"]
            payload = {
                "restaurant_id": int(request.form["restaurant_id"]),
                "name": request.form["name"],
                "description": request.form["description"],
                "price": float(request.form["price"]),
                "is_available": is_available,
                "category": request.form["category"],
            }
            supabase.table("menu_items").insert(payload).execute()
            flash("Menu item created", "ok")
    data = supabase.table("menu_items").select("*").order("item_id").execute()
    restaurants = supabase.table("restaurants").select("*").order("restaurant_id").execute()

    return render_template("menu_items.html",restaurants=restaurants.data, items=data.data, title="Menu")


@app.route("/orders", methods=["GET", "POST"])
@login_required
@admin_required
def orders():
    if request.method == "POST":
        if "__delete_id" in request.form:
            supabase.table("orders").delete().eq("order_id", request.form["__delete_id"]).execute()
            flash("Order deleted", "warn")
        else:
            rid = request.form.get("reservation_id", "").strip()
            payload = {
                "user_id": int(request.form["user_id"]),
                "restaurant_id": int(request.form["restaurant_id"]),
                "reservation_id": int(rid) if rid else None,
                "order_type": request.form["order_type"],
                "total_amount": float(request.form["total_amount"]),
                "status": request.form["status"]
            }
            supabase.table("orders").insert(payload).execute()
            flash("Order created", "ok")
         
    data = supabase.table("orders").select("*").order("order_id").execute()
    reservations = supabase.table("reservations").select("*").order("reservation_id").execute()
    users = supabase.table("users").select("*").order("user_id").execute()
    restaurants = supabase.table("restaurants").select("*").order("restaurant_id").execute()
    return render_template("orders.html", items=data.data,reservations=reservations.data,users=users.data,restaurants=restaurants.data, title="Orders")


@app.route("/waitlist", methods=["GET", "POST"])
@login_required
@admin_required
def waitlist():
    if request.method == "POST":
        if "__delete_id" in request.form:
            supabase.table("waitlist").delete().eq("waitlist_id", request.form["__delete_id"]).execute()
            flash("Waitlist entry deleted", "warn")
        else:
            payload = {
                "restaurant_id": int(request.form["restaurant_id"].split("|")[0]),
                "user_id": int(request.form["user_id"]),
                "party_size": int(request.form["party_size"]),
                "estimated_wait_time": int(request.form["estimated_wait_time"]),
                "status": request.form["status"]
            }
            supabase.table("waitlist").insert(payload).execute()
            flash("Waitlist entry created", "ok")

            now = datetime.datetime.now()
            formatted = now.strftime("%Y-%m-%d %H:%M:%S")
            payload_log={
                "user_id": int(request.form["user_id"]),
                "type": "System",
                "message": f"Added to waitlist at {request.form['restaurant_id'].split("|")[1]} restaurant",
                "status": "Sent",
                "created_at":str(formatted)
            }
            supabase.table("notifications").insert(payload_log).execute()
    data = supabase.table("waitlist").select("*").order("waitlist_id").execute()
    reservations = supabase.table("reservations").select("*").order("reservation_id").execute()
    users = supabase.table("users").select("*").order("user_id").execute()
    restaurants = supabase.table("restaurants").select("*").order("restaurant_id").execute()
    
    return render_template("waitlist.html", items=data.data,reservations=reservations.data,users=users.data,restaurants=restaurants.data, title="Waitlist")


#notifications route
@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    user = session.get("user")

    if not user.get("is_admin"):
        data = supabase.table("notifications").select("*").eq("user_id", user["id"]).execute()
        return render_template("notifications.html", items=data.data, user=user, title="Notifications")

    if request.method == "POST":
        if "__delete_id" in request.form:
            supabase.table("notifications").delete().eq("notification_id", request.form["__delete_id"]).execute()
            flash("Notification deleted", "warn")
        else:
            payload = {
                "user_id": int(request.form["user_id"]),
                "type": request.form["type"],
                "message": request.form["message"],
                "status": request.form["status"]
            }
            supabase.table("notifications").insert(payload).execute()
            flash("Notification created", "ok")

    data = supabase.table("notifications").select("*").order("notification_id").execute()
    return render_template("notifications.html", items=data.data, user=user, title="Notifications")


#old analytics route
# @app.get("/analytics")
# @login_required
# @admin_required
# def analytics():
#     rows = supabase.table("analytics_log").select("*").execute().data
#     by_type = {}
#     for r in rows:
#         et = r.get("event_type")
#         by_type.setdefault(et, {"event_type": et, "count": 0, "sum": 0.0})
#         by_type[et]["count"] += 1
#         by_type[et]["sum"] += float(r.get("value") or 0)
#     by_rest = {}
#     for r in rows:
#         rid = r.get("restaurant_id")
#         by_rest.setdefault(rid, {"restaurant_id": rid, "count": 0})
#         by_rest[rid]["count"] += 1
#     return render_template("analytics.html", by_type=list(by_type.values()), by_rest=list(by_rest.values()), title="Analytics")

@app.get("/analytics")
@login_required
@admin_required
def analytics():
    # Fetch raw data from Supabase
    waitlist_rows = supabase.table("waitlist").select("*").order("waitlist_id").execute().data or []
    reservation_rows = supabase.table("reservations").select("*").order("reservation_id").execute().data or []
    user_rows = supabase.table("users").select("*").order("user_id").execute().data or []
    restaurant_rows = supabase.table("restaurants").select("*").order("restaurant_id").execute().data or []

    # Build restaurant lookup: id -> name
    restaurant_name_by_id = {
        r.get("restaurant_id"): r.get("name")
        for r in restaurant_rows
    }

    # ---------- Reservations by restaurant ----------
    res_stats = {}  # rid -> {restaurant_id, count, party_size_sum}
    for r in reservation_rows:
        rid = r.get("restaurant_id")
        if rid is None:
            continue
        party_size = r.get("party_size") or 0
        if rid not in res_stats:
            res_stats[rid] = {
                "restaurant_id": rid,
                "total_reservations": 0,
                "party_size_sum": 0.0,
            }
        res_stats[rid]["total_reservations"] += 1
        res_stats[rid]["party_size_sum"] += float(party_size)

    reservations_by_restaurant = []
    for rid, stats in res_stats.items():
        count = stats["total_reservations"]
        avg_party_size = stats["party_size_sum"] / count if count > 0 else 0.0
        reservations_by_restaurant.append({
            "restaurant_id": rid,
            "restaurant_name": restaurant_name_by_id.get(rid),
            "total_reservations": count,
            "avg_party_size": avg_party_size,
        })

    # ---------- Waitlist by restaurant ----------
    wl_stats = {}  # rid -> {restaurant_id, count}
    for w in waitlist_rows:
        rid = w.get("restaurant_id")
        if rid is None:
            continue
        if rid not in wl_stats:
            wl_stats[rid] = {
                "restaurant_id": rid,
                "total_waitlisted": 0,
            }
        wl_stats[rid]["total_waitlisted"] += 1

    waitlist_by_restaurant = []
    for rid, stats in wl_stats.items():
        waitlist_by_restaurant.append({
            "restaurant_id": rid,
            "restaurant_name": restaurant_name_by_id.get(rid),
            "total_waitlisted": stats["total_waitlisted"],
        })

    # ---------- Users by role ----------
    role_counts = {}  # role -> count
    for u in user_rows:
        role = u.get("role") or "Unknown"
        role_counts[role] = role_counts.get(role, 0) + 1

    users_by_role = [
        {"role": role, "count": count}
        for role, count in role_counts.items()
    ]

    # Pass through the raw restaurants if you still need them in the template
    restaurants = restaurant_rows

    return render_template(
        "analytics.html",
        reservations_by_restaurant=reservations_by_restaurant,
        waitlist_by_restaurant=waitlist_by_restaurant,
        users_by_role=users_by_role,
        restaurants=restaurants,
        title="Analytics",
    )




if __name__ == "__main__":
    app.run(host='0.0.0.0',debug=True)
