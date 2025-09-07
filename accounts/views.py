from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import CustomUser, OTP
from .serializers import OTPRequestSerializer, OTPVerifySerializer, UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from google.oauth2 import id_token
from google.auth.transport import requests
import random

User = get_user_model()


# -------------------- GOOGLE AUTH --------------------
class GoogleAuthView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"error": "Token is required"}, status=400)
        try:
            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
            )
            email = idinfo.get("email")
            name = idinfo.get("name", "")
            picture = idinfo.get("picture", "")

            if not email:
                return Response({"error": "Email not provided by Google"}, status=400)

            name_parts = name.strip().split(" ", 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": email,
                    "first_name": first_name,
                    "last_name": last_name,
                }
            )

            if created:
                user.set_unusable_password()
                user.email_verified = True
                user.save()

            refresh = RefreshToken.for_user(user)

            return Response({
                "message": "Login successful via Google" if not created else "Registration successful via Google",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": f"{user.first_name} {user.last_name}".strip(),
                    "picture": picture,
                }
            }, status=200)
        except ValueError:
            return Response({"error": "Invalid Google token"}, status=400)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


# -------------------- REGISTER (Send OTP first) --------------------
class RegisterRequest(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        full_name = request.data.get("full_name")
        email = request.data.get("email")
        phone = request.data.get("phone")

        if not full_name or not email or not phone:
            return Response({"error": "All fields are required"}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already registered"}, status=400)

        # Store registration data in session
        request.session['registration_data'] = {
            'full_name': full_name,
            'email': email,
            'phone': phone
        }

        # Generate OTP
        otp_code = str(random.randint(100000, 999999))
        request.session['registration_otp'] = otp_code
        request.session['registration_email'] = email
        request.session['otp_created_at'] = timezone.now().isoformat()

        # Send email
        subject = 'Verify your email address for registration'
        message = f'Your verification code is: {otp_code}. It is valid for 10 minutes.'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)

        return Response({
            "message": "Verification OTP sent to your email. Please verify to complete registration.",
            "email": email
        }, status=200)


# -------------------- REGISTER VERIFICATION --------------------
class RegisterVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        registration_data = request.session.get('registration_data')
        session_otp = request.session.get('registration_otp')
        session_email = request.session.get('registration_email')
        otp_created_at = request.session.get('otp_created_at')

        if not registration_data or not session_otp or not session_email or not otp_created_at:
            return Response({"error": "Registration session expired. Please start again."}, status=400)
        if email != session_email:
            return Response({"error": "Email mismatch."}, status=400)

        created_at = timezone.datetime.fromisoformat(otp_created_at)
        if timezone.now() > created_at + timezone.timedelta(minutes=10):
            return Response({"error": "OTP has expired."}, status=400)
        if otp != session_otp:
            return Response({"error": "Invalid OTP."}, status=400)

        # Create user
        full_name = registration_data['full_name']
        name_parts = full_name.strip().split(" ", 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        user = User.objects.create_user(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone=registration_data['phone'],
            password=None
        )
        user.set_unusable_password()
        user.email_verified = True
        user.save()

        # Clear session
        for key in ['registration_data', 'registration_otp', 'registration_email', 'otp_created_at']:
            if key in request.session:
                del request.session[key]

        login(request, user)

        return Response({
            "message": "Registration successful! Account created and logged in.",
            "user_id": user.id,
            "email": user.email
        }, status=201)


# -------------------- OTP LOGIN --------------------
class OTPRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if not user.email_verified:
                return Response({"error": "Email not verified. Please verify your email first."}, status=400)
            return Response({"message": "OTP has been sent to your email.", "email": user.email}, status=200)
        return Response(serializer.errors, status=400)


class OTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            if not user.email_verified:
                return Response({"error": "Email not verified. Please verify your email first."}, status=400)
            login(request, user)
            OTP.objects.filter(user=user, purpose='login').delete()
            return Response({"message": "Login successful", "user_id": user.id, "email": user.email}, status=200)
        return Response(serializer.errors, status=400)


# -------------------- EMAIL VERIFICATION --------------------
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        try:
            user = User.objects.get(email=email)
            otp_obj = OTP.objects.filter(user=user, otp=otp, purpose='verification').latest('created_at')
            if not otp_obj.is_valid():
                return Response({"error": "OTP has expired."}, status=400)
            user.email_verified = True
            user.save()
            OTP.objects.filter(user=user, purpose='verification').delete()
            return Response({"message": "Email verified successfully."}, status=200)
        except User.DoesNotExist:
            return Response({"error": "No user found with this email address."}, status=400)
        except OTP.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=400)


# -------------------- LOGOUT --------------------
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({"message": "Logout successful"}, status=200)


# -------------------- PROFILE --------------------
class ViewProfile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response({"profile": serializer.data})


class UpdateProfile(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data
        user.first_name = data.get("first_name", user.first_name)
        user.last_name = data.get("last_name", user.last_name)
        user.phone = data.get("phone", user.phone)
        user.address = data.get("address", user.address)

        new_email = data.get("email")
        if new_email and new_email != user.email:
            user.email = new_email
            user.email_verified = False
            otp_obj = OTP.generate_otp(user, purpose='verification')
            subject = 'Verify your new email address'
            message = f'Your verification code is: {otp_obj.otp}. It is valid for 10 minutes.'
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [new_email], fail_silently=False)

        user.save()
        return Response({"message": "Profile updated successfully"})


# -------------------- SUPERUSER LOGIN --------------------
class SuperuserLogin(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user and user.is_superuser:
            login(request, user)
            return Response({"success": True, "message": "Superuser logged in!"})
        return Response({"success": False, "message": "Invalid superuser credentials"})
