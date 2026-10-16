# gunicorn.conf.py
# Runs once in the master process before workers are forked.
# This is the correct place for db.create_all() so workers
# don't race each other on startup.


from datetime import UTC

bind = "0.0.0.0:5000"
workers = 2
timeout = 120
accesslog = "-"


def on_starting(server):
    """Called once by the gunicorn master before workers fork."""
    from app import app, db
    with app.app_context():
        db.create_all()
        # Mark any scans stuck in pending/running from a previous crash as failed.
        from datetime import datetime, timedelta

        from models import Scan
        cutoff = datetime.now(UTC) - timedelta(minutes=10)
        stuck = Scan.query.filter(
            Scan.status.in_(("pending", "running")),
            Scan.started_at < cutoff,
        ).all()
        for s in stuck:
            s.status = "failed"
            s.error_message = "Server restarted while scan was running."
        if stuck:
            db.session.commit()
        print(f"[startup] db.create_all() done. {len(stuck)} stuck scan(s) reset.")