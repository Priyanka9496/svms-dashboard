STATIC_SUGGESTIONS = {
    "migration error": [
        "Run 'python manage.py makemigrations'.",
        "Run 'python manage.py migrate'.",
        "Check if the necessary database tables are present.",
        "Ensure the app is correctly added to INSTALLED_APPS in settings.py."
    ],

    "critical rce found in admin panel": [
        "Restrict access to the admin panel (use a firewall or VPN).",
        "Update Django and all dependencies to the latest secure versions.",
        "Remove unsafe code patterns such as eval/exec and unsafe deserialization.",
        "Set DEBUG=False, configure ALLOWED_HOSTS, enable CSRF protection, and harden XSS settings.",
        "Rotate any exposed keys, tokens, or credentials immediately.",
        "Perform a penetration test before restoring normal access."
    ],

    "content security policy (csp) header not set": [
        "Reason: This happens because the Django app does not send a Content-Security-Policy (CSP) HTTP header, making it vulnerable to XSS and content injection.",
        "Step 1: Install CSP support: pip install django-csp.",
        "Step 2: Add 'csp.middleware.CSPMiddleware' in the MIDDLEWARE list inside settings.py.",
        "Step 3: Add CSP directives in settings.py (CSP_DEFAULT_SRC, CSP_SCRIPT_SRC, CSP_STYLE_SRC, CSP_IMG_SRC, etc.).",
        "Step 4: Restart the Django server or redeploy the application.",
        "Step 5: Verify in the browser: Open Developer Tools → Network → Response Headers and confirm that Content-Security-Policy is present.",
        "Step 6: Validate externally using https://securityheaders.com to ensure no errors."
    ]
}