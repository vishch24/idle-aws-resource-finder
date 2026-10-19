"""
Idle AWS Resource Finder for Learners
Flask application entry point.
"""

from dotenv import load_dotenv

load_dotenv()

import json
import os
import secrets
import threading
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

import scanner as aws_scanner
from aws_session import PERMISSIONS_POLICY, ROLE_ARN_RE, trust_policy, verify
from config import Config
from models import AwsConnection, Finding, Scan, User, UserSettings, db

app = Flask(__name__)
app.config.from_object(Config)

# Principal that AWS trusts to assume the user's role.
# Locally this is your IAM user ARN. On Beanstalk it must be the INSTANCE
# ROLE's ARN (arn:aws:iam::<acct>:role/<name>), set via env var.
app.config["APP_PRINCIPAL_ARN"] = os.environ.get("APP_PRINCIPAL_ARN", "")

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"

STALE_AFTER = timedelta(minutes=10)

IST = ZoneInfo("Asia/Kolkata")

def now_ist():
    """Return naive or timezone-aware datetime in IST."""
    return datetime.now(IST).replace(tzinfo=None)

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


# ---- Helpers -------------------------------------------------------------
def get_or_create_settings(user: User) -> UserSettings:
    if user.settings is None:
        settings = UserSettings(user_id=user.id)
        db.session.add(settings)
        db.session.commit()
    return user.settings


def get_or_create_connection(user: User) -> AwsConnection:
    conn = AwsConnection.query.filter_by(user_id=user.id).first()
    if conn is None:
        conn = AwsConnection(user_id=user.id, external_id=secrets.token_urlsafe(32))
        db.session.add(conn)
        db.session.commit()
    return conn


def _summary_cards(findings):
    buckets = {
        "ec2":      {"count": 0, "inr": 0.0},
        "ebs":      {"count": 0, "inr": 0.0},
        "eip":      {"count": 0, "inr": 0.0},
        "snapshot": {"count": 0, "inr": 0.0},
    }
    for f in findings:
        inr = float(f.monthly_inr or 0)
        rt = f.resource_type
        if "EC2 instance" in rt:
            buckets["ec2"]["count"] += 1
            buckets["ec2"]["inr"] += inr
        elif "EBS volume" in rt:
            buckets["ebs"]["count"] += 1
            buckets["ebs"]["inr"] += inr
        elif "Elastic IP" in rt:
            buckets["eip"]["count"] += 1
            buckets["eip"]["inr"] += inr
        elif "snapshot" in rt.lower():
            buckets["snapshot"]["count"] += 1
            buckets["snapshot"]["inr"] += inr
    for b in buckets.values():
        b["inr"] = round(b["inr"], 2)
    return buckets


# ---- Public routes -------------------------------------------------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        flash("Incorrect email or password.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not name or not email or not password:
            flash("All fields are required.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "danger")
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
            db.session.add(UserSettings(user_id=user.id))
            db.session.add(AwsConnection(user_id=user.id,
                                          external_id=secrets.token_urlsafe(32)))
            db.session.commit()
            login_user(user)
            flash("Account created. Welcome!", "success")
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


# ---- Authenticated routes ------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    latest_scan = (Scan.query.filter_by(user_id=current_user.id, status="completed")
                   .order_by(Scan.started_at.desc()).first())
    findings, summary, total_inr = [], _summary_cards([]), 0.0
    if latest_scan:
        findings = latest_scan.findings.all()
        summary = _summary_cards(findings)
        total_inr = latest_scan.total_inr
    return render_template("dashboard.html", scan=latest_scan, findings=findings,
                           summary=summary, total_inr=total_inr)


def _run_scan_job(app_obj, scan_id, creds, region_arg, use_pricing, cpu_threshold, snapshot_age):
    with app_obj.app_context():
        scan_record = db.session.get(Scan, scan_id)
        try:
            # Constants are mutated per scan. Fine here because scans run
            # one at a time (the /scan route blocks a second scan while one
            # is pending/running) -- do not remove that check below.
            aws_scanner.IDLE_CPU_THRESHOLD = float(cpu_threshold)
            aws_scanner.SNAPSHOT_MAX_AGE_DAYS = int(snapshot_age)

            raw_findings, skipped = aws_scanner.run_scan(
                creds=creds, region=region_arg, use_pricing_api=use_pricing,
            )
            for f in raw_findings:
                db.session.add(Finding(
                    scan_id=scan_record.id, user_id=scan_record.user_id,
                    region=f["region"], resource_type=f["type"], resource_id=f["id"],
                    detail=f.get("detail"), monthly_inr=f.get("monthly_inr"),
                    price_source=f.get("price_source"),
                    upper_bound=bool(f.get("upper_bound", False)),
                    cleanup_command=f.get("cleanup"),
                    priority=Finding.assign_priority(f["type"]),
                ))
            scan_record.status = "completed"
            scan_record.resources_checked = len(raw_findings)
            scan_record.skipped_regions = skipped or None
        except Exception as exc:  # noqa: BLE001 — worker must catch all failures
            db.session.rollback()
            scan_record = db.session.get(Scan, scan_id)
            scan_record.status = "failed"
            scan_record.error_message = str(exc)[:1000]
        scan_record.completed_at = now_ist()
        db.session.commit()


@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    settings = get_or_create_settings(current_user)
    conn = get_or_create_connection(current_user)

    if request.method == "POST":
        if conn.status != "active":
            flash("Connect your AWS account in Settings first.", "warning")
            return redirect(url_for("settings"))

        # 1. Auto-fail scans that exceeded the STALE_AFTER threshold
        Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.status.in_(("pending", "running")),
            Scan.started_at < datetime.now(UTC) - STALE_AFTER,
        ).update({"status": "failed", "error_message": "Timed out"},
                 synchronize_session=False)
        db.session.commit()

        # 2. Check for active scan; if it has been stuck for >2 minutes without progress, auto-fail it
        active_scan = Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.status.in_(("pending", "running")),
        ).first()

        if active_scan:
            # If a scan has been sitting in "pending" for over 2 minutes, the worker died
            age = datetime.now(UTC) - active_scan.started_at.replace(tzinfo=UTC)
            if active_scan.status == "pending" and age > timedelta(minutes=2):
                active_scan.status = "failed"
                active_scan.error_message = "Scan worker failed to start."
                db.session.commit()
            else:
                flash("A scan is currently running. Please wait for it to complete.", "info")
                return redirect(url_for("scan"))

        selected = request.form.getlist("region")
        print("DEBUG selected:", selected, "scan_all_regions:", settings.scan_all_regions)
        if not selected or "all" in selected:
            regions_to_scan = None   # scanner lists all enabled regions
        else:
            regions_to_scan = selected

        try:
            creds, _ = verify(conn.role_arn, conn.external_id)
        except (ClientError, RuntimeError, TypeError) as exc:
            flash(f"Could not use your connected AWS role: {exc}. "
                  f"Reconnect it in Settings.", "danger")
            return redirect(url_for("settings"))

        scan_record = Scan(user_id=current_user.id, connection_id=conn.id,
                           regions=regions_to_scan, status="pending",
                           started_at=now_ist())
        db.session.add(scan_record)
        db.session.commit()

        # Pass None for all regions, a single string if 1 region, or the list
        region_arg = regions_to_scan[0] if (regions_to_scan and len(regions_to_scan) == 1) else regions_to_scan

        app_obj = app
        threading.Thread(
            target=_run_scan_job,
            args=(app_obj, scan_record.id, creds, region_arg,
                  bool(settings.include_pricing), settings.cpu_threshold,
                  settings.snapshot_age_days),
            daemon=True,
        ).start()
        flash("Scan started...", "success")
        return redirect(url_for('scan_progress', scan_id=scan_record.id))

    recent_scans = (Scan.query.filter_by(user_id=current_user.id)
                     .order_by(Scan.started_at.desc()).limit(10).all())
    return render_template("scans.html", settings=settings, recent_scans=recent_scans)

@app.route("/scan/reset", methods=["POST"])
@login_required
def reset_scan():
    Scan.query.filter(
        Scan.user_id == current_user.id,
        Scan.status.in_(("pending", "running")),
    ).update(
        {"status": "failed", "error_message": "Manually cancelled by user."},
        synchronize_session=False,
    )
    db.session.commit()
    flash("Stuck scans have been reset. You can now start a new scan.", "success")
    return redirect(url_for("scan"))


@app.route("/scan/<int:scan_id>/progress")
@login_required
def scan_progress(scan_id):
    s = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template("scan_progress.html", scan_id=scan_id,
                           regions=s.regions)


@app.route("/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    s = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return jsonify(status=s.status, error=s.error_message,
                   skipped_regions=s.skipped_regions)


@app.post("/scan/<int:scan_id>/delete")
@login_required
def delete_scan(scan_id):
    scan = Scan.query.filter_by(
        id=scan_id, user_id=current_user.id
    ).first_or_404()

    force = request.args.get("force", "false").lower() == "true"

    # Only prevent deletion if it's genuinely running and not a forced delete
    if scan.status == "running" and not force:
        flash("Cannot delete a scan that is actively running.", "warning")
        return redirect(url_for("scan"))
    db.session.delete(scan)
    db.session.commit()
    flash(f"Scan SCAN-{scan_id} and its findings deleted.", "success")
    return redirect(url_for("scan"))
    

@app.route("/findings")
@login_required
def findings():
    # Allow drilling into a specific scan via ?scan_id=N
    scan_id = request.args.get("scan_id", type=int)

    if scan_id:
        target_scan = Scan.query.filter_by(
            id=scan_id, user_id=current_user.id, status="completed"
        ).first_or_404()
    else:
        target_scan = (
            Scan.query
            .filter_by(user_id=current_user.id, status="completed")
            .order_by(Scan.started_at.desc())
            .first()
        )

    all_findings = target_scan.findings.all() if target_scan else []
    total_inr    = sum(float(f.monthly_inr or 0) for f in all_findings)
    high_count   = sum(1 for f in all_findings if f.priority == "High")

    return render_template(
        "findings.html",
        findings=all_findings,
        scan=target_scan,
        total_inr=round(total_inr, 2),
        high_count=high_count,
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user_settings = get_or_create_settings(current_user)
    conn = get_or_create_connection(current_user)
    connect_error = None

    if not app.config["APP_PRINCIPAL_ARN"]:
        flash("Server misconfigured: APP_PRINCIPAL_ARN is not set.", "danger")

    if request.method == "POST":
        if "role_arn" in request.form:
            role_arn = request.form.get("role_arn", "").strip()
            if not ROLE_ARN_RE.match(role_arn):
                connect_error = "That doesn't look like an IAM role ARN."
            else:
                try:
                    _, ident = verify(role_arn, conn.external_id)
                except (ClientError, RuntimeError) as exc:
                    connect_error = (
                        "Couldn't assume that role. Check the trust policy, "
                        f"external ID, and permissions. ({exc})"
                    )
                else:
                    conn.role_arn = role_arn
                    conn.account_id = ident["Account"]
                    conn.status = "active"
                    db.session.commit()
                    flash("AWS account connected.", "success")
                    return redirect(url_for("settings"))
        else:
            current_user.name = request.form.get("fullName", current_user.name).strip()
            current_user.email = request.form.get("email", current_user.email).strip().lower()

            # connection_method has only one real value now. Never trust the
            # form for this -- a user could POST cli_profile by hand.
            user_settings.connection_method = "iam_role"
            chosen = request.form.get("defaultRegion", "all")
            user_settings.default_region = chosen

            threshold_map = {"Below 3%": 3.0, "Below 5%": 5.0, "Below 10%": 10.0}
            user_settings.cpu_threshold = threshold_map.get(
                request.form.get("cpuThreshold", ""), 5.0)
            age_map = {"Older than 30 days": 30, "Older than 60 days": 60,
                       "Older than 90 days": 90, "Older than 180 days": 180}
            user_settings.snapshot_age_days = age_map.get(
                request.form.get("snapshotAge", ""), 90)
            user_settings.include_pricing = "pricing" in request.form
            user_settings.scan_all_regions = (chosen == "all")
            user_settings.scan_notifications = "scanNotifications" in request.form
            user_settings.cost_notifications = "costNotifications" in request.form
            db.session.commit()
            flash("Settings saved.", "success")
            return redirect(url_for("settings"))

    return render_template(
        "settings.html", settings=user_settings, conn=conn, connect_error=connect_error,
        trust_json=json.dumps(trust_policy(app.config["APP_PRINCIPAL_ARN"],
                                            conn.external_id), indent=2),
        perms_json=json.dumps(PERMISSIONS_POLICY, indent=2),
    )


@app.route('/health')
def health_check():
    # Helpful for AWS Application Load Balancer (ALB) health checks
    return jsonify({"status": "healthy"}), 200


# ---- Create tables ---------------------------------------------------
# Only creates tables that don't exist yet. If you change a model's columns,
# this will NOT alter the existing table -- drop and recreate the database,
# or add an ALTER TABLE by hand.
# with app.app_context():
#     db.create_all()
#     stuck_count = Scan.query.filter(
#         Scan.status.in_(("pending", "running"))
#     ).update(
#         {"status": "failed", "error_message": "Terminated due to application restart."},
#         synchronize_session=False,
#     )
#     if stuck_count > 0:
#         db.session.commit()
#         print(f"Startup check: Cleared {stuck_count} stuck scan(s).")

if __name__ == "__main__":
    app.run(debug=False)