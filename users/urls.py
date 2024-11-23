# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
# Provide a unique basename for each viewset
router.register(r'students', StudentViewSet, basename='student')


urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('api/', include(router.urls)),
    path('studentsyllabus/', StudentSyllabusListCreateView.as_view(), name='studentsyllabus-list-create'),
    path('studentsyllabus/<int:pk>/', StudentSyllabusRetrieveUpdateDeleteView.as_view(), name='studentsyllabus-detail'),
    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-request/validate/', PasswordResetValidateView.as_view(), name='password-reset-validate'),
    path('ResetPasswordByEmail/', ResetPasswordByEmail.as_view(), name='ResetPasswordByEmail'),
]


