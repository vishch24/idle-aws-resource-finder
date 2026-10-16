"""
Flask configuration.
Values are read from environment variables so they never live in code.
On Beanstalk, set these under Configuration > Software > Environment properties.
Locally, put them in a .env file and load with python-dotenv.
"""

from dotenv import load_dotenv

load_dotenv()

import os
from typing import ClassVar


class Config:
    # ---- Security -------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-before-deploy")

    # ---- Database -------------------------------------------------------
    # Format: mysql+pymysql://user:password@host:3306/dbname
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "mysql+pymysql://root:root@localhost:3306/idle_aws_finder",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict] = {
        "pool_recycle": 280,   # recycle before MySQL's wait_timeout (default 300s)
        "pool_pre_ping": True,
    }

    # ---- AWS scanning ---------------------------------------------------
    # Exchange rate used for INR conversion. Override with an env var.
    USD_TO_INR = float(os.environ.get("USD_TO_INR", "88.0"))

    # ---- Session --------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
