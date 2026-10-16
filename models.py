"""
SQLAlchemy models.

Relationships:
  User  ──< Scans    (one user has many scans)
  User  ──< Findings (denormalised shortcut: user_id on findings)
  Scan  ──< Findings (one scan has many findings)
  User  ──1 UserSettings (one-to-one, created on first login)
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

IST = ZoneInfo("Asia/Kolkata")

def now_ist():
    return datetime.now(IST).replace(tzinfo=None)

class AwsConnection(db.Model):
    __tablename__ = "aws_connections"
 
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                            nullable=False, unique=True)
    external_id = db.Column(db.String(64), nullable=False)
    role_arn    = db.Column(db.String(256))
    account_id  = db.Column(db.String(12))
    status      = db.Column(db.Enum("pending", "active"), default="pending")
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # relationships
    scans    = db.relationship("Scan",         back_populates="user", lazy="dynamic")
    findings = db.relationship("Finding",      back_populates="user", lazy="dynamic")
    settings = db.relationship("UserSettings", back_populates="user", uselist=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.email}>"


class UserSettings(db.Model):
    __tablename__ = "user_settings"

    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                                   nullable=False, unique=True)
    connection_method  = db.Column(db.Enum("iam_role"), default="iam_role")
    default_region     = db.Column(db.String(50), default="all")
    cpu_threshold      = db.Column(db.Numeric(4, 1), default=5.0)
    snapshot_age_days  = db.Column(db.Integer, default=90)
    include_pricing    = db.Column(db.Boolean, default=True)
    scan_all_regions = db.Column(db.Boolean, default=True, nullable=False)
    scan_notifications = db.Column(db.Boolean, default=True)
    cost_notifications = db.Column(db.Boolean, default=True)

    user = db.relationship("User", back_populates="settings")

    def __repr__(self) -> str:
        return f"<UserSettings user_id={self.user_id}>"


class Scan(db.Model):
    __tablename__ = "scans"

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                                  nullable=False)
    connection_id     = db.Column(db.Integer, db.ForeignKey("aws_connections.id", ondelete="CASCADE"),
                                  nullable=False)
    regions           = db.Column(db.JSON)
    status            = db.Column(
                            db.Enum("pending", "running", "completed", "failed"),
                            default="pending",
                        )
    started_at        = db.Column(db.DateTime, default=now_ist)
    completed_at      = db.Column(db.DateTime, nullable=True)
    resources_checked = db.Column(db.Integer, default=0)
    skipped_regions   = db.Column(db.JSON)
    error_message     = db.Column(db.Text)

    user     = db.relationship("User",    back_populates="scans")
    findings = db.relationship("Finding", back_populates="scan",
                               lazy="dynamic", cascade="all, delete-orphan")

    @property
    def total_inr(self) -> float:
        """Sum of non-null monthly_inr across all findings."""
        return sum(
            float(f.monthly_inr) for f in self.findings if f.monthly_inr is not None
        )

    @property
    def finding_count(self) -> int:
        return self.findings.count()

    def __repr__(self) -> str:
        return f"<Scan id={self.id} user_id={self.user_id} status={self.status}>"


class Finding(db.Model):
    __tablename__ = "findings"

    id              = db.Column(db.Integer, primary_key=True)
    scan_id         = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"),
                                nullable=False)
    user_id         = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                                nullable=False)
    region          = db.Column(db.String(50),  nullable=False)
    resource_type   = db.Column(db.String(100), nullable=False)
    resource_id     = db.Column(db.String(100), nullable=False)
    detail          = db.Column(db.Text)
    monthly_inr     = db.Column(db.Numeric(10, 2))
    price_source    = db.Column(db.String(50))
    upper_bound     = db.Column(db.Boolean, default=False)
    cleanup_command = db.Column(db.Text)
    priority        = db.Column(db.Enum("High", "Medium", "Low"), default="Medium")
    created_at      = db.Column(db.DateTime, default=now_ist)

    scan = db.relationship("Scan", back_populates="findings")
    user = db.relationship("User", back_populates="findings")

    @staticmethod
    def assign_priority(resource_type: str) -> str:
        """Assign priority based on resource type string from scanner.py."""
        if "EC2 instance" in resource_type:
            return "High"
        if "EBS volume" in resource_type or "Elastic IP" in resource_type:
            return "Medium"
        return "Low"   # snapshots and anything else

    def __repr__(self) -> str:
        return f"<Finding {self.resource_type} {self.resource_id}>"