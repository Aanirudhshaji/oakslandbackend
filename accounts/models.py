# models.py
import random
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

class CustomUser(AbstractUser):
    phone = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    
    def __str__(self):
        return self.email


class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    purpose = models.CharField(max_length=20, default='login')  # login, verification, etc.
    
    def is_valid(self):
        # OTP expires after 10 minutes
        return timezone.now() < self.created_at + timedelta(minutes=10)
    
    @classmethod
    def generate_otp(cls, user, purpose='login'):
        # Delete any existing OTPs for this user and purpose
        cls.objects.filter(user=user, purpose=purpose).delete()
        
        # Generate a 6-digit OTP
        otp_code = str(random.randint(100000, 999999))
        
        # Create and return the OTP object
        return cls.objects.create(user=user, otp=otp_code, purpose=purpose)





# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from rest_framework.decorators import api_view, permission_classes
# from django.contrib.auth import get_user_model, authenticate, login, logout
# from .models import CustomUser

# User = get_user_model()


# # -------------------- LOGIN --------------------
# class LoginRequest(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         email = request.data.get("email")
#         password = request.data.get("password")

#         if not email or not password:
#             return Response({"error": "Username and password required"}, status=400)

#         user = authenticate(email=email, password=password)
#         if user is not None:
#             login(request, user)
#             return Response({"message": "Login successful", "user_id": user.id})
#         else:
#             return Response({"error": "Invalid email or password"}, status=400)


# # -------------------- REGISTER --------------------
# class RegisterRequest(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         full_name = request.data.get("full_name")
#         email = request.data.get("email")
#         phone = request.data.get("phone")
#         password = request.data.get("password")
#         re_password = request.data.get("re_password")

#         if not full_name or not email or not phone or not password or not re_password:
#             return Response({"error": "All fields are required"}, status=400)

#         if password != re_password:
#             return Response({"error": "Passwords do not match"}, status=400)

#         if User.objects.filter(email=email).exists():
#             return Response({"error": "Email already registered"}, status=400)

#         name_parts = full_name.strip().split(" ", 1)
#         first_name = name_parts[0]
#         last_name = name_parts[1] if len(name_parts) > 1 else ""

#         user = User.objects.create_user(
#             username=email,  
#             email=email,
#             first_name=first_name,
#             last_name=last_name,
#             phone=phone,
#             password=password
#         )

#         return Response({"message": "Registration successful", "user_id": user.id}, status=201)


# # -------------------- LOGOUT --------------------
# class LogoutView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         logout(request)
#         return Response({"message": "Logout successful"}, status=200)


# # -------------------- PROFILE --------------------
# class ViewProfile(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         user = request.user
#         data = {
#             "username": user.username,
#             "email": user.email,
#             "first_name": user.first_name,
#             "last_name": user.last_name,
#             "phone": user.phone,
#             "address": user.address,
#         }
#         return Response({"profile": data})


# class UpdateProfile(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         user = request.user
#         data = request.data

#         # Update fields if present
#         user.first_name = data.get("first_name", user.first_name)
#         user.last_name = data.get("last_name", user.last_name)
#         user.email = data.get("email", user.email)
#         user.phone = data.get("phone", user.phone)
#         user.address = data.get("address", user.address)

#         user.save()
#         return Response({"message": "Profile updated successfully"})


# # -------------------- SUPERUSER LOGIN --------------------
# class SuperuserLogin(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         username = request.data.get("username")
#         password = request.data.get("password")

#         user = authenticate(username=username, password=password)
#         if user and user.is_superuser:
#             login(request, user)
#             return Response({"success": True, "message": "Superuser logged in!"})
#         return Response({"success": False, "message": "Invalid superuser credentials"})



