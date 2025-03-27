🔐 SVMS – Security Vulnerability Management System
A web-based dashboard for managing, tracking, and assigning security vulnerabilities. Built with Django, Bootstrap, and integrated scanning tools like ZAP.

Features
🔍 Start and monitor security scans

📊 Visualize vulnerabilities by severity

🧑‍💻 Assign vulnerabilities to users

📄 View detailed vulnerability descriptions and suggested solutions

📤 Export reports as CSV or PDF

🧩 Modular API with Django REST Framework

🟢 Real-time scan progress bar

**Tech Stack**
Backend: Django, Django REST Framework

Frontend: HTML, Bootstrap, JavaScript

Database: PostgreSQL (or SQLite during development)

Task Queue: Celery + Redis (if used)

Scanner Integration: OWASP ZAP


**Setup Instructions**
# 1. Clone the repository
git clone https://github.com/Priyanka9496/svms-dashboard.git
cd svms-dashboard

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up your .env file
cp .env.example .env  # Then fill in your DB creds, CELERY, etc.

# 5. Apply migrations
python manage.py migrate

# 6. Run the server
python manage.py runserver

Example .env
DEBUG=True
SECRET_KEY=your-secret-key
DB_NAME=svms_db
DB_USER=svms_user
DB_PASSWORD=yourpassword
DB_HOST=localhost
DB_PORT=5432
CELERY_BROKER_URL=redis://localhost:6379/0
