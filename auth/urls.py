"""
URL configuration for auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path ,include
from google_auth.views import GoogleLogin, TrialView

from myauthentication.views import DashboardView

urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('auth/api/',include('myauthentication.urls')),
    # path('social_auth/api/',include('google_auth.urls')),
    
    path('dj-rest-auth/', include('dj_rest_auth.urls')),
    path('dj-rest-auth/registration/', include('dj_rest_auth.registration.urls')),
    path('dj-rest-auth/google/', GoogleLogin.as_view(), name='google_login'),
    path('google/login/', TrialView.as_view(), name='trial_view'),
    
    path('dashboard/',DashboardView.as_view(),name = "dashboard"),
]
