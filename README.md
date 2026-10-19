# Idle AWS Resource Finder for Learners

A web app that scans your AWS account for forgotten resources, shows the estimated monthly waste in rupees, and gives you the exact CLI command to clean each one up.

---

## System Design

<img src="https://github.com/vishch24/idle-aws-resource-finder/blob/main/diagram/system-design.png" width="100%" height="100%">

---

## Project Structure

```
idle-aws-resource-finder/
├── app.py                  # Flask routes and app factory
├── scanner.py              # AWS resource finders and run_scan()
├── aws_session.py          # STS AssumeRole helpers and policy builders
├── models.py               # SQLAlchemy models
├── config.py               # Configuration from environment variables
├── schema.sql              # Reference schema (db.create_all() builds tables)
├── requirements.txt
├── .env.example
├── .gitignore
└── templates/
    ├── base.html
    ├── base_auth.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── scans.html
    ├── scan_progress.html
    ├── findings.html
    └── settings.html
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, Flask, boto3 |
| Database | MySQL on Amazon RDS (SQLAlchemy + PyMySQL) |
| Frontend | Bootstrap 5.3, Bootstrap Icons, DataTables |
| Auth | Flask-Login, Werkzeug password hashing |
| AWS | Elastic Beanstalk (Python platform), STS AssumeRole, EC2, CloudWatch, Price List API |
| CI/CD | GitHub Actions |
| Config | python-dotenv |

---

## CI/CD Pipeline

Every push to `main` runs a 7-stage DevSecOps pipeline via GitHub Actions:

1. **Secret scanning** — Gitleaks scans git history for leaked credentials
2. **Code lint** — Ruff checks Python syntax and style
3. **Dependency audit** — pip-audit checks all packages against the CVE database
4. **Container security** — Hadolint lints the Dockerfile; Trivy scans the built image for HIGH and CRITICAL CVEs
5. **Image push** — scanned image is tagged with the commit SHA and pushed to Docker Hub
6. **Deploy** — docker-compose bundle deployed to AWS Elastic Beanstalk (Docker platform)
7. **DAST** — OWASP ZAP baseline scan runs against the live deployed URL

> **Note on Trivy findings:** The image scan may report CVEs in packages
> under `pip/_vendor/`. These are pip's own internal copies bundled inside
> the pip release itself, not application dependencies. They are never
> called by the Flask app. The application-level packages in `site-packages`
> are fully patched. These CVEs are suppressed via `.trivyignore` with the
> rationale documented in that file.

---

## The Problem

AWS learners and small teams forget to shut down resources after practice sessions. Idle EC2 instances, unattached EBS volumes, unused Elastic IPs, and old snapshots keep billing quietly in the background. AWS billing tools exist, but they are built for enterprises. This app is built for learners.

---

## How It Works

1. Register and open Settings.
2. Create a read-only IAM role in your AWS account using the trust policy and permissions policy shown on the page.
3. Paste the role ARN into Settings and click Verify & Connect.
4. Run a scan. The app assumes your role with temporary STS credentials, scans your account across all enabled regions, and saves the findings.
5. Review the findings on the Dashboard or the Findings page. Each finding shows the resource ID, region, estimated monthly cost in rupees, and the CLI command to clean it up.

The app never stores your AWS access keys. It uses a read-only cross-account IAM role with a per-user external ID. It never modifies or deletes any resource.

---

## Features

### Scanning
- Detects five resource types across all enabled AWS regions in parallel:
  - **Idle EC2 instances** — running but average CPU stayed below the threshold for 7 days
  - **Stopped EC2 instances** — no compute cost, but attached EBS disks keep billing
  - **Unattached EBS volumes** — status is `available`, not attached to any instance
  - **Unused Elastic IPs** — allocated but not associated with any resource
  - **Old EBS snapshots** — older than the configured age, source volume may be deleted
- Fetches live regional prices from the AWS Price List API where permitted, falls back to built-in estimates otherwise
- Shows estimated monthly waste in rupees with the live USD to INR rate
- Shows the exact AWS CLI cleanup command for every finding, with a one-click copy button
- Marks snapshot costs as upper bounds since AWS only bills for data actually stored

### Dashboard
- Summary cards showing count and estimated monthly cost for EC2, EBS, Elastic IPs, and Snapshots
- Findings table with search, sort, and pagination via DataTables
- Shows the last scan date and total estimated monthly waste

### Scan management
- Region selector: choose specific regions or scan all enabled regions
- Scan progress page with live status polling and automatic redirect to findings on completion
- Scan history table with View and Delete buttons per completed scan
- View opens findings filtered to that scan
- Delete prompts for inline confirmation before removing the scan and all its findings
- Stuck scans (server restart during a scan) are automatically cleaned up on startup

### Findings
- Filterable and searchable findings table
- Filter by resource type and priority (High, Medium, Low)
- Priority assigned automatically: EC2 instances are High, EBS volumes and Elastic IPs are Medium, Snapshots are Low
- Breadcrumb showing which scan is currently displayed

### Security
- Cross-account IAM role with a server-generated external ID per user — the app never holds long-lived credentials for any user's account
- STS temporary credentials (15-minute session) used per scan and discarded
- All findings, scans, and connections are scoped to the owning user — no cross-user data leakage
- Read-only IAM permissions: `ec2:Describe*`, `cloudwatch:GetMetricStatistics`, `pricing:GetProducts`
- Flask-Login with hashed passwords
- `connection_method` is fixed to `iam_role` server-side regardless of form input

### Settings
- Per-user scan preferences: CPU threshold, snapshot age, default region, include pricing estimates
- Connect and reconnect an AWS account at any time
- Scan and cost notification toggles

---

## Local Setup

### Prerequisites
- Python 3.11 or higher
- MySQL running locally
- AWS CLI configured with an IAM user that has `sts:AssumeRole` permission

### Running with Local Environment (Python Virtual Environment)

```bash
# Clone the repo
git clone https://github.com/vishch24/idle-aws-resource-finder.git
cd idle-aws-resource-finder

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create the database
mysql -u root -p -e "CREATE DATABASE idle_aws_finder;"

# Copy the example env file and fill in your values
cp .env.example .env
```

Edit `.env`:
```dotenv
APP_PRINCIPAL_ARN=arn:aws:iam::<your-account-id>:user/<your-iam-user>
SECRET_KEY=<a-long-random-string>
DATABASE_URL=mysql+pymysql://root:<password>@localhost:3306/idle_aws_finder
USD_TO_INR=88.0
```

```bash
# Run the app (creates tables automatically on first run)
gunicorn --config gunicorn.conf.py app:app
```

### Using Docker Compose (Local Development)

```bash
# Clone the repo and navigate into the directory
git clone https://github.com/vishch24/idle-aws-resource-finder.git
cd idle-aws-resource-finder

# Copy the example environment file and configure your values
cp .env.example .env

# Build and start the services (Flask app + MySQL) in detached mode
docker compose -f docker-compose-local.yml up -d --build

# View container logs
docker compose -f docker-compose-local.yml logs

# Stop the services when done
docker compose -f docker-compose-local.yml down
```

Open `http://127.0.0.1:5000`.

---

## AWS IAM Setup

### 1. Find your app's caller ARN
```bash
aws sts get-caller-identity --query Arn --output text
```

### 2. Create the role in your AWS account
Go to IAM → Roles → Create role → Custom trust policy. The trust policy and permissions policy are generated for you on the Settings page once you register and log in.

---

## Future Enhancements

- **Scheduled daily scans** — automatically scan each connected account once a day and notify on new findings
- **Email alerts** — send a weekly digest of estimated waste to the user's email
- **Remediation tracking** — let users mark a finding as "resolved" or "ignore" so it doesn't reappear on the next scan
- **Cost trend chart** — show estimated monthly waste over time so users can see whether their cleanup efforts are working
- **Multi-account support** — let one user connect more than one AWS account and compare findings across them
- **Terraform and CloudFormation one-click role setup** — instead of manual IAM steps, a downloadable template that creates the role in one click
- **Per-resource drill-down** — click a finding to see CloudWatch metrics, attached resources, and the full tag set
- **Slack or Teams notification** — post a summary to a channel when a scan finishes
- **CSV and PDF export** — download findings for offline review or sharing with a team lead
- **Support for more resource types** — RDS idle instances, unused NAT gateways, orphaned load balancers, Lambda functions with no invocations
- **Worker tier for background scans** — move scans from a Flask background thread to a proper Beanstalk worker tier with an SQS queue so the web tier stays responsive under load

---

## Built With

This project was built as part of the **AWS Elastic Beanstalk Community Hackathon** organised by the **TrainWithShubham** community.

---

## Author

**Vishakha Chavan**   
Full Stack Developer transitioning into DevOps Engineering    
[GitHub](https://github.com/vishch24) · [LinkedIn](https://linkedin.com/in/vishakha-chavan24)
