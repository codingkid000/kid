from rest_framework import serializers
from .models import *
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from rest_framework.validators import UniqueValidator
from datetime import datetime

class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        max_length=150,
        validators=[UniqueValidator(queryset=CustomUser.objects.all(), message="This username is already taken.")]
    )
    email = serializers.EmailField(
        validators=[UniqueValidator(queryset=CustomUser.objects.all(), message="This email is already registered.")]
    )

    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email')
# Serializer for Registration
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'password', 'email')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        try:
            # Create a new user with provided username, email, and password
            user = CustomUser.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password'],
            )
            return user
        except Exception as e:
            raise serializers.ValidationError(f"Registration failed: {str(e)}")
        



class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = '__all__'




class StudentSyllabusSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentSyllabus
        fields = ['id', 'user', 'date', 'activity', 'mentor', 'hour']

    def validate(self, attrs):
        errors = {}
       
        if not attrs.get('user'):
            errors['user'] = "This field may not be blank."
        
       
        if not attrs.get('date'):
            errors['date'] = "This field may not be blank."
        
        if not attrs.get('activity'):
            errors['activity'] = "This field may not be blank."

        if not attrs.get('mentor'):
            errors['mentor'] = "This field may not be blank."

        if not attrs.get('hour'):
            errors['hour'] = "This field may not be blank."

        if errors:
            raise serializers.ValidationError(errors)
        
        return attrs

    def to_representation(self, instance):
      
        representation = super().to_representation(instance)
        return representation
    


class UpStudentSyllabusSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentSyllabus
        fields = ['user', 'date', 'activity', 'mentor', 'hour']

    def validate_date(self, value):
        try:
            # Check if date format is correct (YYYY-MM-DD)
            datetime.strptime(str(value), '%Y-%m-%d')
        except ValueError:
            raise serializers.ValidationError("Date has wrong format. Use one of these formats instead: YYYY-MM-DD.")
        return value

    def validate_activity(self, value):
        if not value:
            raise serializers.ValidationError("This field may not be blank.")
        return value

    def validate_mentor(self, value):
        if not value:
            raise serializers.ValidationError("This field may not be blank.")
        return value

    def validate_hour(self, value):
        if not value:
            raise serializers.ValidationError("This field may not be blank.")
        return value
    





class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()




class PasswordResetValidateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8)

    def validate(self, data):
        email = data.get("email")
        otp = data.get("otp")

        try:
            password_reset_request = PasswordResetRequest.objects.get(otp=otp, user__email=email)
        except PasswordResetRequest.DoesNotExist:
            print(f"Invalid OTP or email: OTP={otp}, Email={email}")  # Log invalid attempts
            raise serializers.ValidationError({"otp": "Invalid OTP"})

        if password_reset_request.is_expired():
            print(f"OTP expired: OTP={otp}, Expired at={password_reset_request.expires_at}")
            raise serializers.ValidationError({"otp": "OTP has expired"})

        data["user"] = password_reset_request.user
        data["password_reset_request"] = password_reset_request
        return data