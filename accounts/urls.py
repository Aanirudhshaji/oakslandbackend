
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('request-otp/', views.OTPRequestView.as_view(), name='request_otp'),
    path('verify-otp/', views.OTPVerifyView.as_view(), name='verify_otp'),
    path('register/', views.RegisterRequest.as_view(), name='register'),
    path('register-verify/', views.RegisterVerifyView.as_view(), name='register_verify'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('profile/', views.ViewProfile.as_view(), name='view_profile'),
    path('update-profile/', views.UpdateProfile.as_view(), name='update_profile'),
    path('superuser-login/', views.SuperuserLogin.as_view(), name='superuser_login'),
    path("api/auth/google/", views.GoogleAuthView.as_view(), name="google_auth"),
]

# from django.urls import path
# from .views import (
#     LoginRequest,
#     RegisterRequest,
#     LogoutView,
#     ViewProfile,
#     UpdateProfile,
#     SuperuserLogin,
# )



# urlpatterns = [
#     path("login/", LoginRequest.as_view(), name="login"),
#     path("register/", RegisterRequest.as_view(), name="register"),
#     path("logout/", LogoutView.as_view(), name="logout"),
#     path("profile/view/", ViewProfile.as_view(), name="view_profile"),
#     path("profile/update/", UpdateProfile.as_view(), name="update_profile"),
#     path("superuser/login/", SuperuserLogin.as_view(), name="superuser_login"),
# ]
