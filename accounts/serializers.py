# serializers.py
from rest_framework import serializers
from .models import CustomUser, OTP
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate


# -------------------- USER --------------------
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "phone",
            "address",
            "email_verified",
        ]


# -------------------- REGISTER --------------------
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["full_name", "email", "phone", "password"]

    def create(self, validated_data):
        # split full name
        full_name = validated_data["full_name"].strip().split(" ", 1)
        first_name = full_name[0]
        last_name = full_name[1] if len(full_name) > 1 else ""

        # create inactive user
        user = CustomUser.objects.create_user(
            username=validated_data["email"],
            email=validated_data["email"],
            first_name=first_name,
            last_name=last_name,
            phone=validated_data["phone"],
            password=validated_data["password"],
        )
        user.is_active = False
        user.email_verified = False
        user.save()

        # generate OTP
        otp_obj = OTP.generate_otp(user, purpose="verification")

        # send OTP email
        subject = "Verify your email"
        message = f"Your verification code is: {otp_obj.otp}. It is valid for 10 minutes."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        return user


# -------------------- LOGIN --------------------
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        user = authenticate(username=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email or password")

        if not user.email_verified:
            raise serializers.ValidationError("Email not verified. Please verify first.")

        data["user"] = user
        return data


# -------------------- OTP REQUEST (for login only) --------------------
class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = CustomUser.objects.get(email=value)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No user found with this email address.")

        if not user.email_verified:
            raise serializers.ValidationError("Email not verified. Please verify first.")

        return value

    def save(self):
        email = self.validated_data["email"]
        user = CustomUser.objects.get(email=email)
        otp_obj = OTP.generate_otp(user, purpose="login")

        # Send OTP via email
        subject = "Your Login OTP Code"
        message = f"Your OTP for login is: {otp_obj.otp}. It is valid for 10 minutes."
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

        return user


# -------------------- OTP VERIFY (for login) --------------------
class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data.get("email")
        otp = data.get("otp")

        try:
            user = CustomUser.objects.get(email=email)
            otp_obj = OTP.objects.filter(user=user, otp=otp, purpose="login").latest("created_at")

            if not otp_obj.is_valid():
                raise serializers.ValidationError("OTP has expired.")

            data["user"] = user
            return data

        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No user found with this email address.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
