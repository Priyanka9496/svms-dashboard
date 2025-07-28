from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from svms.views import index
from django.conf import settings
from django.conf.urls.static import static
import os

urlpatterns = [
    path('', index, name='index'),
    # path("api/users/", get_users, name="get_users"),
    # path("api/assign_vulnerability/", assign_vulnerability, name="assign_vulnerability"),
    path('', include('svms.urls')),
    path('api/securetrack/', include('securetrack.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('admin/', admin.site.urls),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=os.path.join(settings.BASE_DIR, 'securetrack/static'))