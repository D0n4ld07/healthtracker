import os
import sqlite3
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from functools import wraps

# -----------------------------
# App & Security config
# -----------------------------
app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "devkey_change_me")
app.config["WTF_CSRF_TIME_LIMIT"] = None  # keep dev-friendly
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "health.db")

# -----------------------------
# Helpers
# -----------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    # meals
    c.execute("""
    CREATE TABLE IF NOT EXISTS meal_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        meal_type TEXT NOT NULL,
        food TEXT NOT NULL,
        calories INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    # fitness
    c.execute("""
    CREATE TABLE IF NOT EXISTS fitness_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        duration_min INTEGER NOT NULL,
        calories_burned INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    # sleep
    c.execute("""
    CREATE TABLE IF NOT EXISTS sleep_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sleep_start TEXT NOT NULL,
        sleep_end TEXT NOT NULL,
        duration_hours REAL NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    # weight
    c.execute("""
    CREATE TABLE IF NOT EXISTS weight_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        weight_kg REAL NOT NULL,
        height_cm REAL NOT NULL,
        bmi REAL NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    # goals (one row per user)
    c.execute("""
    CREATE TABLE IF NOT EXISTS goals(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        target_weight_kg REAL,
        daily_calorie_intake_target INTEGER,
        daily_exercise_minutes_target INTEGER,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth"))
        return view(*args, **kwargs)
    return wrapper

def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    conn.close()
    return user

def parse_date(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def start_end_from_range(range_key: str, start_str=None, end_str=None):
    today = date.today()
    if range_key == "today":
        return today, today
    if range_key == "week":
        # ISO week: Monday start
        start = today - timedelta(days=today.weekday())
        end = start + timedelta(days=6)
        return start, end
    if range_key == "month":
        start = today.replace(day=1)
        # next month start - 1 day
        if start.month == 12:
            next_start = date(start.year + 1, 1, 1)
        else:
            next_start = date(start.year, start.month + 1, 1)
        end = next_start - timedelta(days=1)
        return start, end
    if range_key == "custom" and start_str and end_str:
        return parse_date(start_str), parse_date(end_str)
    # all: return None to indicate unbounded
    return None, None

def to_dt(dt_str: str) -> datetime:
    # supports 'YYYY-MM-DDTHH:MM' or 'YYYY-MM-DD HH:MM'
    dt_str = dt_str.strip()
    if "T" in dt_str:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
    return datetime.strptime(dt_str, "%Y-%m-%d %H:%M")

def fmt_day(d: date) -> str:
    return d.strftime("%Y-%m-%d")

def ensure_goals_row(user_id: int):
    conn = get_db()
    cur = conn.execute("SELECT id FROM goals WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    if not row:
        conn.execute("""
        INSERT INTO goals(user_id, target_weight_kg, daily_calorie_intake_target, daily_exercise_minutes_target, updated_at)
        VALUES (?, NULL, NULL, NULL, ?)
        """, (user_id, datetime.utcnow().isoformat()))
        conn.commit()
    conn.close()

# -----------------------------
# Auth
# -----------------------------
@app.route("/auth", methods=["GET", "POST"])
@csrf.exempt  # we will manually include csrf for forms; GET safe
def auth():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "register":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()
            if not username or not email or not password:
                flash("All fields are required for registration.", "error")
                return redirect(url_for("auth"))
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return redirect(url_for("auth"))
            pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            try:
                conn = get_db()
                conn.execute(
                    "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                    (username, email, pw_hash, datetime.utcnow().isoformat()))
                conn.commit()
                conn.close()
                flash("Registration successful. Please log in.", "success")
            except sqlite3.IntegrityError:
                flash("Username or email already exists.", "error")
            return redirect(url_for("auth"))
        elif action == "login":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()
            conn = get_db()
            cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cur.fetchone()
            conn.close()
            if user and bcrypt.check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                flash("Welcome back!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth"))
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("auth.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("auth"))

# -----------------------------
# Dashboard & Goals
# -----------------------------
@app.route("/")
@login_required
def dashboard():
    user = current_user()
    uid = user["id"]

    today = date.today()
    start, end = today, today
    start_str, end_str = fmt_day(start), fmt_day(end)

    conn = get_db()
    # meals today
    cur = conn.execute("SELECT COALESCE(SUM(calories),0) AS total FROM meal_logs WHERE user_id=? AND date=?",
                       (uid, start_str))
    total_in = cur.fetchone()["total"]

    # fitness today
    cur = conn.execute("""SELECT COALESCE(SUM(calories_burned),0) AS total,
                                 COALESCE(SUM(duration_min),0) AS mins
                          FROM fitness_logs WHERE user_id=? AND date=?""",
                       (uid, start_str))
    row = cur.fetchone()
    total_out = row["total"]
    total_mins = row["mins"]

    # avg sleep last 7 days
    cur = conn.execute("""SELECT COALESCE(AVG(duration_hours),0) AS avg_h
                          FROM sleep_logs
                          WHERE user_id=? AND DATE(sleep_end) >= DATE('now','-6 day')""", (uid,))
    avg_sleep = round(cur.fetchone()["avg_h"] or 0, 2)

    # latest BMI
    cur = conn.execute("""SELECT bmi FROM weight_logs WHERE user_id=? ORDER BY date DESC, id DESC LIMIT 1""", (uid,))
    row = cur.fetchone()
    last_bmi = row["bmi"] if row else None

    # goals
    ensure_goals_row(uid)
    cur = conn.execute("SELECT * FROM goals WHERE user_id=?", (uid,))
    goals = cur.fetchone()
    conn.close()

    # compute diffs
    diffs = {"weight": None, "calorie": None, "exercise": None}
    suggestions = []

    # weight diff: latest weight - target
    conn = get_db()
    cur = conn.execute("SELECT weight_kg FROM weight_logs WHERE user_id=? ORDER BY date DESC, id DESC LIMIT 1", (uid,))
    wrow = cur.fetchone()
    conn.close()
    if goals and goals["target_weight_kg"] is not None and wrow:
        diffs["weight"] = round(wrow["weight_kg"] - goals["target_weight_kg"], 2)
        if diffs["weight"] > 0:
            suggestions.append("Aim for a daily calorie deficit of 300–500 kcal and do 30–45 minutes of moderate cardio today.")
        elif diffs["weight"] < 0:
            suggestions.append("Aim for a small surplus of +200–300 kcal and focus on strength training.")

    if goals and goals["daily_calorie_intake_target"] is not None:
        diffs["calorie"] = goals["daily_calorie_intake_target"] - total_in
        if diffs["calorie"] < 0:
            suggestions.append("You've exceeded today's intake target; go light for dinner and add some walking.")

    if goals and goals["daily_exercise_minutes_target"] is not None:
        diffs["exercise"] = goals["daily_exercise_minutes_target"] - total_mins
        if diffs["exercise"] > 0:
            suggestions.append(f"You still need {diffs['exercise']} minutes of exercise today (e.g., brisk walk/jog/cycle).")

    return render_template("dashboard.html",
                           total_in=total_in,
                           total_out=total_out,
                           avg_sleep=avg_sleep,
                           last_bmi=last_bmi,
                           diffs=diffs,
                           goals=goals,
                           suggestions=suggestions)

@app.route("/goals", methods=["GET", "POST"])
@login_required
def goals():
    user = current_user()
    uid = user["id"]
    ensure_goals_row(uid)

    if request.method == "POST":
        tgt_w = request.form.get("target_weight_kg")
        tgt_c = request.form.get("daily_calorie_intake_target")
        tgt_m = request.form.get("daily_exercise_minutes_target")
        def conv(v, t):
            try:
                return t(v) if v not in (None, "",) else None
            except: return None
        vals = (conv(tgt_w, float), conv(tgt_c, int), conv(tgt_m, int), datetime.utcnow().isoformat(), uid)
        conn = get_db()
        conn.execute("""UPDATE goals SET
                        target_weight_kg=?,
                        daily_calorie_intake_target=?,
                        daily_exercise_minutes_target=?,
                        updated_at=?
                        WHERE user_id=?""", vals)
        conn.commit()
        conn.close()
        flash("Goals updated.", "success")
        return redirect(url_for("goals"))

    conn = get_db()
    row = conn.execute("SELECT * FROM goals WHERE user_id=?", (uid,)).fetchone()
    conn.close()
    return render_template("goals.html", goals=row)

# -----------------------------
# Logs CRUD
# -----------------------------
@app.route("/meals", methods=["GET", "POST"])
@login_required
def meals():
    uid = session["user_id"]
    if request.method == "POST":
        dt = request.form.get("date")
        meal_type = request.form.get("meal_type") or "Breakfast"
        food = request.form.get("food","").strip()
        calories = int(request.form.get("calories") or 0)
        if not dt or not food or calories <= 0:
            flash("Please provide a valid meal entry.", "error")
            return redirect(url_for("meals"))
        conn = get_db()
        conn.execute("""INSERT INTO meal_logs(user_id,date,meal_type,food,calories,created_at)
                        VALUES(?,?,?,?,?,?)""",
                     (uid, dt, meal_type, food, calories, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        flash("Meal log added.", "success")
        return redirect(url_for("meals"))
    conn = get_db()
    rows = conn.execute("""SELECT * FROM meal_logs WHERE user_id=? ORDER BY date DESC, id DESC""", (uid,)).fetchall()
    conn.close()
    return render_template("meal_log.html", rows=rows)

@app.route("/meals/<int:rid>/delete", methods=["POST"])
@login_required
def meals_delete(rid):
    uid = session["user_id"]
    conn = get_db()
    conn.execute("DELETE FROM meal_logs WHERE id=? AND user_id=?", (rid, uid))
    conn.commit()
    conn.close()
    flash("Meal log deleted.", "success")
    return redirect(url_for("meals"))

@app.route("/fitness", methods=["GET", "POST"])
@login_required
def fitness():
    uid = session["user_id"]
    if request.method == "POST":
        dt = request.form.get("date")
        activity = request.form.get("activity_type","").strip()
        duration = int(request.form.get("duration_min") or 0)
        burned = int(request.form.get("calories_burned") or 0)
        if not dt or not activity or duration <= 0 or burned < 0:
            flash("Please provide a valid fitness entry.", "error")
            return redirect(url_for("fitness"))
        conn = get_db()
        conn.execute("""INSERT INTO fitness_logs(user_id,date,activity_type,duration_min,calories_burned,created_at)
                        VALUES(?,?,?,?,?,?)""",
                     (uid, dt, activity, duration, burned, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        flash("Fitness log added.", "success")
        return redirect(url_for("fitness"))
    conn = get_db()
    rows = conn.execute("""SELECT * FROM fitness_logs WHERE user_id=? ORDER BY date DESC, id DESC""", (uid,)).fetchall()
    conn.close()
    return render_template("fitness_log.html", rows=rows)

@app.route("/fitness/<int:rid>/delete", methods=["POST"])
@login_required
def fitness_delete(rid):
    uid = session["user_id"]
    conn = get_db()
    conn.execute("DELETE FROM fitness_logs WHERE id=? AND user_id=?", (rid, uid))
    conn.commit()
    conn.close()
    flash("Fitness log deleted.", "success")
    return redirect(url_for("fitness"))

@app.route("/sleep", methods=["GET", "POST"])
@login_required
def sleep():
    uid = session["user_id"]
    if request.method == "POST":
        s = request.form.get("sleep_start")
        e = request.form.get("sleep_end")
        if not s or not e:
            flash("Please provide both sleep start and end.", "error")
            return redirect(url_for("sleep"))
        try:
            s_dt = to_dt(s)
            e_dt = to_dt(e)
            if e_dt < s_dt:
                e_dt = e_dt + timedelta(days=1)
            duration_h = round((e_dt - s_dt).total_seconds() / 3600.0, 2)
            if duration_h <= 0:
                raise ValueError("duration invalid")
        except Exception:
            flash("Invalid datetime format.", "error")
            return redirect(url_for("sleep"))
        conn = get_db()
        conn.execute("""INSERT INTO sleep_logs(user_id,sleep_start,sleep_end,duration_hours,created_at)
                        VALUES(?,?,?,?,?)""",
                     (uid, s_dt.isoformat(sep=" "), e_dt.isoformat(sep=" "), duration_h, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        flash("Sleep log added.", "success")
        return redirect(url_for("sleep"))
    conn = get_db()
    rows = conn.execute("""SELECT * FROM sleep_logs WHERE user_id=? ORDER BY sleep_start DESC, id DESC""", (uid,)).fetchall()
    conn.close()
    return render_template("sleep_log.html", rows=rows)

@app.route("/sleep/<int:rid>/delete", methods=["POST"])
@login_required
def sleep_delete(rid):
    uid = session["user_id"]
    conn = get_db()
    conn.execute("DELETE FROM sleep_logs WHERE id=? AND user_id=?", (rid, uid))
    conn.commit()
    conn.close()
    flash("Sleep log deleted.", "success")
    return redirect(url_for("sleep"))

@app.route("/weight", methods=["GET", "POST"])
@login_required
def weight():
    uid = session["user_id"]
    if request.method == "POST":
        dt = request.form.get("date")
        weight_kg = float(request.form.get("weight_kg") or 0)
        height_cm = float(request.form.get("height_cm") or 0)
        if not dt or weight_kg <= 0 or height_cm <= 0:
            flash("Please provide valid weight/height.", "error")
            return redirect(url_for("weight"))
        bmi = round(weight_kg / ((height_cm / 100.0) ** 2), 2)
        conn = get_db()
        conn.execute("""INSERT INTO weight_logs(user_id,date,weight_kg,height_cm,bmi,created_at)
                        VALUES(?,?,?,?,?,?)""",
                     (uid, dt, weight_kg, height_cm, bmi, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        flash("Weight log added.", "success")
        return redirect(url_for("weight"))
    conn = get_db()
    rows = conn.execute("""SELECT * FROM weight_logs WHERE user_id=? ORDER BY date DESC, id DESC""", (uid,)).fetchall()
    conn.close()
    return render_template("weight_log.html", rows=rows)

@app.route("/weight/<int:rid>/delete", methods=["POST"])
@login_required
def weight_delete(rid):
    uid = session["user_id"]
    conn = get_db()
    conn.execute("DELETE FROM weight_logs WHERE id=? AND user_id=?", (rid, uid))
    conn.commit()
    conn.close()
    flash("Weight log deleted.", "success")
    return redirect(url_for("weight"))

# -----------------------------
# Charts page + API
# -----------------------------
@app.route("/charts")
@login_required
def charts():
    return render_template("charts.html")

def aggregate_query(uid, table, value_col, date_col, start=None, end=None, group_by="day"):
    """
    Returns (labels, values) aggregated by day/week/month using SQLite strftime.
    """
    conn = get_db()
    params = [uid]
    where = "WHERE user_id=?"
    if start and end:
        where += f" AND DATE({date_col}) BETWEEN ? AND ?"
        params.extend([fmt_day(start), fmt_day(end)])
    # group key
    if group_by == "month":
        grp = f"strftime('%Y-%m', {date_col})"
    elif group_by == "week":
        # week number; combine with year to avoid merging across years
        grp = f"strftime('%Y-W%W', {date_col})"
    else:
        grp = f"strftime('%Y-%m-%d', {date_col})"
    sql = f"SELECT {grp} AS g, COALESCE(SUM({value_col}),0) AS v FROM {table} {where} GROUP BY g ORDER BY g"
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    labels = [r["g"] for r in rows]
    values = [r["v"] for r in rows]
    return labels, values

@app.route("/api/charts/<kind>")
@login_required
def api_charts(kind):
    uid = session["user_id"]
    range_key = request.args.get("range", "all")
    group_by = request.args.get("group_by", "day")
    start_str = request.args.get("start")
    end_str = request.args.get("end")
    start, end = start_end_from_range(range_key, start_str, end_str)

    if kind == "weight":
        # return both weight and BMI (line)
        conn = get_db()
        params = [uid]
        where = "WHERE user_id=?"
        if start and end:
            where += " AND DATE(date) BETWEEN ? AND ?"
            params.extend([fmt_day(start), fmt_day(end)])
        grp_map = {"day": "%Y-%m-%d", "week": "%Y-W%W", "month": "%Y-%m"}
        fmt = grp_map.get(group_by, "%Y-%m-%d")
        sql = f"""SELECT strftime('{fmt}', date) AS g,
                         AVG(weight_kg) AS w, AVG(bmi) AS b
                  FROM weight_logs {where} GROUP BY g ORDER BY g"""
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        conn.close()
        labels = [r["g"] for r in rows]
        return jsonify({
            "labels": labels,
            "series": [
                {"name": "Weight (kg)", "data": [round(r["w"] or 0, 2) for r in rows]},
                {"name": "BMI", "data": [round(r["b"] or 0, 2) for r in rows]},
            ],
            "meta": {"range": range_key, "group_by": group_by}
        })

    if kind == "meals":
        labels, values = aggregate_query(uid, "meal_logs", "calories", "date", start, end, group_by)
        return jsonify({"labels": labels, "series": [{"name": "Calories In", "data": values}], "meta": {"range": range_key, "group_by": group_by}})

    if kind == "fitness":
        metric = request.args.get("metric", "calories")  # calories|duration
        col = "calories_burned" if metric == "calories" else "duration_min"
        labels, values = aggregate_query(uid, "fitness_logs", col, "date", start, end, group_by)
        return jsonify({"labels": labels, "series": [{"name": ("Calories Burned" if col=="calories_burned" else "Duration (min)"), "data": values}], "meta": {"range": range_key, "group_by": group_by}})

    if kind == "sleep":
        labels, values = aggregate_query(uid, "sleep_logs", "duration_hours", "sleep_end", start, end, group_by)
        return jsonify({"labels": labels, "series": [{"name": "Sleep (h)", "data": [round(v,2) for v in values]}], "meta": {"range": range_key, "group_by": group_by}})

    abort(404)

# -----------------------------
# Index redirect
# -----------------------------
@app.route("/index")
def index_redirect():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("auth"))

# -----------------------------
# Jinja helpers (csrf in plain forms)
# -----------------------------
@app.context_processor
def inject_csrf():
    # Flask-WTF will provide csrf_token() callable in templates
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    init_db()
    # session cookie safety flags (dev-safe defaults)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    # In production behind HTTPS, also set: SESSION_COOKIE_SECURE=True
    app.run(debug=True)
