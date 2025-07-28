from rest_framework import generics
from .models import Comment, UserProfile
from svms.models import Vulnerability as Bug
from .serializers import BugSerializer, CommentSerializer
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render, redirect, get_object_or_404
from django.core.paginator import Paginator
from collections import Counter
from .helpers import STATIC_SUGGESTIONS
import csv
import time
import random
import requests
from .decorators import role_required
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.contrib.auth.decorators import login_required
from .forms import RoleRequestForm, ProfileUpdateForm
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User
from django.contrib.auth import login
from django.contrib import messages
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import openai
import json
import os

openai_apikey = settings.OPENAI_API_KEY
HUGGINGFACE_API_KEY = settings.HUGGINGFACE_API_KEY


SEVERITY_ORDER = {
    'Critical': 1,
    'High': 2,
    'Medium': 3,
    'Low': 4
}


def dashboard_view(request):
    severity_filter = request.GET.get('severity')

    queryset = Bug.objects.exclude(severity__iexact="Informational")
    severity_counts = Counter(v.severity for v in queryset)
    labels = ['Critical', 'High', 'Medium', 'Low']
    data = [severity_counts.get(s, 0) for s in labels]

    if severity_filter:
        queryset = queryset.filter(severity__iexact=severity_filter)
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if start_date:
        queryset = queryset.filter(detected_at__date__gte=start_date)

    if end_date:
        queryset = queryset.filter(detected_at__date__lte=end_date)
    # Annotate manually by Python since Django ORM can't sort custom order easily
    queryset = sorted(queryset, key=lambda x: SEVERITY_ORDER.get(x.severity, 5))

    paginator = Paginator(queryset, 6)  # Show 6 per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Only allow PMs and QAs to assign
    assignable_users = []
    if hasattr(request.user, 'userprofile') and request.user.userprofile.role in ['PM', 'QA']:
        assignable_users = User.objects.filter(is_active=True)

    return render(request, 'securetrack/dashboard.html', {
        'page_obj': page_obj,
        'selected_severity': severity_filter,
        'chart_labels': labels,
        'chart_data': data,
        'assignable_users': assignable_users,
    })

class BugListView(generics.ListCreateAPIView):
    serializer_class = BugSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Bug.objects.exclude(severity__iexact="Informational").order_by('-detected_at')

        severity = self.request.query_params.get('severity')
        vuln_type = self.request.query_params.get('vuln_type')
        assigned_to = self.request.query_params.get('assigned_to')

        if severity:
            queryset = queryset.filter(severity__iexact=severity)

        if vuln_type:
            queryset = queryset.filter(vuln_type__iexact=vuln_type)

        if assigned_to:
            queryset = queryset.filter(assigned_to__username__iexact=assigned_to)

        return queryset

class BugDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Bug.objects.all()
    serializer_class = BugSerializer
    permission_classes = [IsAuthenticated]

class CommentListCreateView(generics.ListCreateAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        bug_id = self.kwargs['pk']
        return Comment.objects.filter(bug_id=bug_id)

    def perform_create(self, serializer):
        bug_id = self.kwargs['pk']
        serializer.save(user=self.request.user, bug_id=bug_id)

def export_csv(request):
    severity = request.GET.get('severity')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    queryset = Bug.objects.exclude(severity__iexact="Informational")

    if severity:
        queryset = queryset.filter(severity__iexact=severity)
    if start_date:
        queryset = queryset.filter(detected_at__date__gte=start_date)
    if end_date:
        queryset = queryset.filter(detected_at__date__lte=end_date)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vulnerabilities.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Name', 'Type', 'Severity', 'Detected At', 'Assigned To'])

    for vuln in queryset:
        writer.writerow([
            vuln.id,
            vuln.name,
            vuln.vuln_type,
            vuln.severity,
            vuln.detected_at.strftime('%Y-%m-%d %H:%M'),
            vuln.assigned_to.username if vuln.assigned_to else 'Unassigned'
        ])

    return response

@role_required(['QA', 'PM'])
def update_bug_status(request, bug_id):
    if request.method == "POST":
        bug = get_object_or_404(Bug, id=bug_id)
        new_status = request.POST.get('status')
        try:
            role = request.user.userprofile.role
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Access denied: No profile found.")
        if role in ['QA', 'PM']:
            bug.status = new_status
            bug.save()
        return redirect('securetrack-dashboard')

@login_required
def user_profile_view(request):
    profile = ensure_user_profile(request.user)
    return render(request, 'securetrack/user_profile.html', {'profile': profile})

def ensure_user_profile(user):
    profile, created = UserProfile.objects.get_or_create(user=user)
    return profile

@login_required
def request_user_profile(request):
    if hasattr(request.user, 'userprofile'):
        if not request.user.userprofile.is_approved:
            return render(request, 'securetrack/profile_pending.html')
        return redirect('securetrack-dashboard')

    if request.method == 'POST':
        form = RoleRequestForm(request.POST)
        if form.is_valid():
            user_profile = form.save(commit=False)
            user_profile.user = request.user
            user_profile.save()
            return render(request, 'securetrack/profile_pending.html')
    else:
        form = RoleRequestForm()

    return render(request, 'securetrack/request_profile.html', {'form': form})

@login_required
def update_user_profile(request):
    profile = ensure_user_profile(request.user)

    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            return redirect('user-profile')
    else:
        form = ProfileUpdateForm(instance=profile)

    return render(request, 'securetrack/edit_profile.html', {'form': form})

@login_required
def audit_log_view(request):
    return render(request, 'securetrack/audit_log.html')

@login_required
def export_pdf_view(request):
    return HttpResponse("PDF export will be implemented here.", content_type="text/plain")

@login_required
def schedule_report_view(request):
    return HttpResponse("Scheduled report feature coming soon!", content_type="text/plain")

def register_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
        else:
            user = User.objects.create_user(username=username, password=password)
            login(request, user)
            return redirect('request-profile')
    return render(request, 'securetrack/register.html')

@role_required(['QA', 'PM'])
def assign_bug(request, bug_id):
    bug = get_object_or_404(Bug, id=bug_id)
    if request.method == 'POST':
        if request.content_type == 'application/json':
            import json
            data = json.loads(request.body.decode('utf-8'))
            user_id = data.get('assigned_to')
            if user_id:
                user = get_object_or_404(User, id=user_id)
                bug.assigned_to = user
                bug.save()
                return JsonResponse({'assigned_to': user.username})
            return JsonResponse({'error': 'No user selected'}, status=400)
        else:
            user_id = request.POST.get('assigned_to')
            if user_id:
                user = get_object_or_404(User, id=user_id)
                bug.assigned_to = user
                bug.save()
                return redirect('securetrack-dashboard')
            else:
                return HttpResponseForbidden("No user selected.")
    else:
        return HttpResponseForbidden("Only POST allowed for assignment.")


@csrf_exempt
@require_POST
def chatbot_reply(request):
    try:
        data = json.loads(request.body)
        thinking_messages = [
            "🤖 Thinking...",
            "💭 Let me analyze that...",
            "☁️ Processing your request..."
        ]
        # Pick a random thinking message
        thinking = random.choice(thinking_messages)

        # Short pause to feel natural (optional)
        time.sleep(1)
        user_message = data.get("message")
        if not user_message:
            return JsonResponse({"reply": "No message provided"}, status=400)

        normalized = user_message.lower()

        for key, steps in STATIC_SUGGESTIONS.items():
            key_lower = key.lower()
            if key in normalized:
                ai_reply = "\n".join(f"{i+1}. {step}" for i, step in enumerate(steps))
                return JsonResponse({"reply": ai_reply})

        model = "mistralai/Mixtral-8x7B-Instruct-v0.1"
        api_url = f"https://api-inference.huggingface.co/models/{model}"

        headers = {
            "Authorization": f"Bearer {HUGGINGFACE_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "inputs": f"User: {user_message}\nAI:",
            "parameters": {"max_new_tokens": 250, "temperature": 0.7},
        }

        response = requests.post(api_url, headers=headers, json=payload)

        # Safely parse JSON
        try:
            result = response.json()
        except ValueError:
            return JsonResponse({
                "reply": f"AI service returned an unexpected response: {response.text[:200]}"
            }, status=502)

        # Handle Hugging Face response
        if isinstance(result, list) and "generated_text" in result[0]:
            ai_reply = result[0]["generated_text"]. split("AI:")[-1].strip()
        elif isinstance(result, dict) and "error" in result:
            ai_reply = f"Error from Hugging Face: {result['error']}"
        else:
            ai_reply = str(result)

        return JsonResponse({"reply": ai_reply})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse(
            {"reply": f"Sorry, something went wrong. ({str(e)})"},
            status=500
        )
