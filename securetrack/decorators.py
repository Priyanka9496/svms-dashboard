from django.http import HttpResponseForbidden
from functools import wraps

def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseForbidden("You must be logged in.")

            if not hasattr(request.user, 'userprofile'):
                return HttpResponseForbidden("No profile assigned.")

            if not request.user.userprofile.is_approved:
                return HttpResponseForbidden("Your profile is not approved yet.")

            if request.user.userprofile.role not in allowed_roles:
                return HttpResponseForbidden("Access denied for your role.")

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
