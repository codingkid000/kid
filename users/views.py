from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import *
from rest_framework import viewsets 
from rest_framework import generics
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.views import exception_handler
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.utils import timezone
from datetime import timedelta

class LoginView(APIView):
    def post(self, request):
        # Check if refresh token is provided
        refresh_token = request.data.get('refreshtoken')

        # If a refresh token is provided, validate it and return a success message
        if refresh_token:
            try:
                # Decode the refresh token to get user information
                refresh = RefreshToken(refresh_token)
                user_id = refresh['user_id']  # Extract user_id from the token payload
                user = CustomUser.objects.get(id=user_id)  # Fetch user from the database
                
                # Return success response with user details
                return Response({
                    'success': True,
                    'message': 'Login successful',
                    'field': 'login',
                    'data': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email
                    }
                }, status=status.HTTP_200_OK)

            except (TokenError, InvalidToken) as e:
                # If the refresh token is invalid, return error
                return Response({
                    'success': False,
                    'errors': [{
                        'field': 'refreshtoken',
                        'message': 'Invalid or expired refresh token.'
                    }]
                }, status=status.HTTP_401_UNAUTHORIZED)
            except CustomUser.DoesNotExist:
                # If the user associated with the refresh token doesn't exist
                return Response({
                    'success': False,
                    'errors': [{
                        'field': 'refreshtoken',
                        'message': 'User not found with this refresh token.'
                    }]
                }, status=status.HTTP_401_UNAUTHORIZED)

        # If no refresh token is provided, proceed with normal login (username and password)
        login_input = request.data.get('username')
        password = request.data.get('password')

        # Check if login or password is missing
        if not login_input or not password:
            errors = []
            if not login_input:
                errors.append({
                    "field": "username",
                    "message": "This field is required."
                })
            if not password:
                errors.append({
                    "field": "password",
                    "message": "This field is required."
                })
            return Response({
                'success': False,
                'errors': errors
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if the input is an email
        if '@' in login_input:
            try:
                # Check if a user with this email exists
                user_obj = CustomUser.objects.get(email=login_input)
                user = authenticate(request, username=user_obj.username, password=password)
                
                # If password is incorrect, respond with invalid password
                if user is None:
                    return Response({
                        'success': False,
                        'errors': [
                            {
                                "field": "password",
                                "message": "Invalid password"
                            }
                        ]
                    }, status=status.HTTP_401_UNAUTHORIZED)
            except CustomUser.DoesNotExist:
                # If the email does not exist, return a specific error message for email
                return Response({
                    'success': False,
                    'errors': [
                        {
                            "field": "email",
                            "message": "Invalid email"
                        }
                    ]
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            # Try to authenticate using username
            user = authenticate(request, username=login_input, password=password)

            # If authentication fails due to incorrect password
            if user is None:
                try:
                    # Check if the username exists
                    CustomUser.objects.get(username=login_input)
                    return Response({
                        'success': False,
                        'errors': [
                            {
                                "field": "password",
                                "message": "Invalid password"
                            }
                        ]
                    }, status=status.HTTP_401_UNAUTHORIZED)
                except CustomUser.DoesNotExist:
                    # If the username does not exist at all
                    return Response({
                        'success': False,
                        'errors': [
                            {
                                "field": "username",
                                "message": "Invalid username"
                            }
                        ]
                    }, status=status.HTTP_401_UNAUTHORIZED)

        # If authentication succeeds, return the success response with tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            'success': True,
            'message': 'Login successful',
            'refresh': str(refresh),
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)



class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": True, "message": "User registered successfully"},
                status=status.HTTP_200_OK
            )
        # Transforming serializer errors into the desired format
        error_list = []
        for field, messages in serializer.errors.items():
            for message in messages:
                error_list.append({"field": field, "message": message})
        
        return Response(
            {"success": False, "errors": error_list},
            status=status.HTTP_400_BAD_REQUEST
        )





class StudentViewSet(viewsets.ModelViewSet):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({
                "success": True,
                "message": "Student created successfully.",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            errors = [
                {"field": field, "message": message[0]}
                for field, message in e.detail.items()
            ]
            return Response({"success": False, "errors": errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response({
                "success": True,
                "message": "Student updated successfully.",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except ValidationError as e:
            errors = [
                {"field": field, "message": message[0]}
                for field, message in e.detail.items()
            ]
            return Response({"success": False, "errors": errors}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({
            "success": True,
            "message": "Student deleted successfully."
        }, status=status.HTTP_200_OK)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "success": True,
            "message": "Students retrieved successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "success": True,
            "message": "Student retrieved successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)




class StudentSyllabusListCreateView(ListCreateAPIView):
    queryset = StudentSyllabus.objects.all()
    serializer_class = StudentSyllabusSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            # Include the `id` field explicitly in the response
            return Response({
                "success": True,
                "message": "Student syllabus created successfully.",
                "data": serializer.data  # `serializer.data` will include the `id`
            }, status=status.HTTP_200_OK)
        except ValidationError as exc:
            # Custom error response for validation errors
            errors = [
                {"field": field, "message": message[0]}
                for field, message in exc.detail.items()
            ]
            return Response({
                "success": False,
                "errors": errors
            }, status=status.HTTP_400_BAD_REQUEST)

    def handle_exception(self, exc):
       
        response = exception_handler(exc, self.get_exception_handler_context())

        if response is not None and isinstance(exc, serializers.ValidationError):
            errors = [
                {"field": field, "message": message[0]}
                for field, message in exc.detail.items()
            ]
            return Response({
                "success": False,
                "errors": errors
            }, status=status.HTTP_400_BAD_REQUEST)

        return response



class StudentSyllabusRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = StudentSyllabus.objects.all()
    serializer_class = StudentSyllabusSerializer

    def handle_exception(self, exc):
      
        response = exception_handler(exc, self.request)

        if response is not None and isinstance(exc, ValidationError):
            errors = []
            for field, messages in exc.detail.items():
                if isinstance(messages, list):
                    for msg in messages:
                        errors.append({"field": field, "message": msg})
                else:
                    errors.append({"field": field, "message": messages})

            return Response({
                "success": False,
                "errors": errors
            }, status=status.HTTP_400_BAD_REQUEST)

        return response

    def put(self, request, *args, **kwargs):
        try:
            response = super().update(request, *args, **kwargs)
            return Response({
                "success": True,
                "message": "The data has been updated successfully.",
                "data": response.data
            }, status=status.HTTP_200_OK)
        except ValidationError as exc:
            return self.handle_exception(exc)

    def delete(self, request, *args, **kwargs):
        try:
            super().destroy(request, *args, **kwargs)
            return Response({
                "success": True,
                "message": "The data has been deleted successfully."
            }, status=status.HTTP_200_OK)
        except ValidationError as exc:
            return self.handle_exception(exc)
        


class PasswordResetRequestView(generics.CreateAPIView):
    serializer_class = PasswordResetRequestSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')

        # Validate email presence
        if not email:
            return Response({
                'success': False,
                'errors': [
                    {
                        'field': 'email',
                        'message': 'This field is required.'
                    }
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if the email exists in the database
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({
                'success': False,
                'errors': [
                    {
                        'field': 'email',
                        'message': 'Enter a valid email.'
                    }
                ]
            }, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP and expiration time
        otp = PasswordResetRequest.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=10)  # OTP expires in 10 minutes

        # Create a password reset request
        password_reset_request = PasswordResetRequest.objects.create(
            user=user,
            otp=otp,
            expires_at=expires_at
        )

        # Send OTP via email with proper error handling
        try:
            send_mail(
        subject='Password Reset OTP',
        message=f'Your OTP for resetting the password is: {otp}',
        from_email='harilalfeathers@gmail.com',  # Use your email
        recipient_list=[email],
        fail_silently=False
            )
            
        except Exception as e:  
            return Response({
        "success": False,
        "errors": [
            {
                "field": "email",
                "message": f"Failed to send OTP. Error: {str(e)}"
            }
        ]
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Successful response
        return Response({
            'success': True,
            'message': 'OTP sent to your email'
        }, status=status.HTTP_200_OK)




class PasswordResetValidateView(generics.UpdateAPIView):
    serializer_class = PasswordResetValidateSerializer

    def update(self, request, *args, **kwargs):
        otp = request.data.get('otp')
        new_password = request.data.get('password')

     
        if not otp or not new_password:
            errors = []
            if not otp:
                errors.append({"field": "otp", "message": "This field is required."})
            if not new_password:
                errors.append({"field": "password", "message": "This field is required."})
            return Response({
                'success': False,
                'errors': errors
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
          
            password_reset_request = PasswordResetRequest.objects.get(otp=otp)
        except PasswordResetRequest.DoesNotExist:
            return Response({
                'success': False,
                'errors': [{"field": "otp", "message": "Invalid OTP."}]
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if OTP is expired
        if password_reset_request.is_expired():
            return Response({
                'success': False,
                'errors': [{"field": "otp", "message": "OTP expired."}]
            }, status=status.HTTP_400_BAD_REQUEST)


        user = password_reset_request.user
        user.set_password(new_password)
        user.save()

        password_reset_request.delete()    
        
        return Response({
            'success': True,
            'message': 'Password successfully updated.'
        }, status=status.HTTP_200_OK)
    


class ResetPasswordByEmail(APIView):
    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')

        if not email or not new_password:
            return Response({
                'success': False,
                'errors': [
                    {"field": "email", "message": "Email is required"} if not email else {},
                    {"field": "new_password", "message": "New password is required"} if not new_password else {},
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
          
            user = CustomUser.objects.get(email=email)
            
    
            user.set_password(new_password)
            user.save()

            return Response({
                'success': True,
                'message': 'Password successfully updated.'
            }, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({
                'success': False,
                'errors': [
                    {"field": "email", "message": "Invalid email"}
                ]
            }, status=status.HTTP_400_BAD_REQUEST)