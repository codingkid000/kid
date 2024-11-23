from django.contrib.auth.models import AbstractUser
from django.db import models
import random
import string
from django.utils import timezone

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('staff', 'Staff'),
        ('student', 'Student'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='staff',null=True)
    email = models.EmailField(unique=True) 


class PasswordResetRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

   
    def is_expired(self):
        return timezone.now() > self.expires_at

    @staticmethod
    def generate_otp():
        return ''.join(random.choices(string.digits, k=6))



class Student(models.Model):
    studentName = models.CharField(max_length=100,null=True)
    email=models.CharField(max_length=100,null=True)
    gender=models.CharField(max_length=100,null=True)
    mobileNumber=models.IntegerField(null=True)
    collegeName=models.CharField(max_length=100,null=True)
    mentor = models.CharField(max_length=100,null=True)
    program=models.CharField(max_length=100,null=True)
    programType = models.CharField(max_length=100,null=True)
    joiningDate=models.DateField(null=True)
    courseDuration =models.DecimalField(max_digits=5, decimal_places=2,default=0.00,null=True)


    

class StudentSyllabus(models.Model):
    user=models.ForeignKey(Student,on_delete=models.CASCADE,null=True,blank=True)
    date=models.DateField(null=True)
    activity=models.CharField(max_length=100,null=True)
    mentor=models.CharField(max_length=100,null=True)
    hour=models.CharField(max_length=100,null=True)

