# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django.contrib import messages
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# Create your models here.


class UserManager(models.Manager):
    def validate(self, request):
        errors = False
        ###########################################################
        # validations here
        if len(request.POST['fname']) < 2:
            messages.error(request,'First name must be at least 2 characters!')
            errors = True  
        if not request.POST['fname'].isalpha():
            messages.error(request,"First name should be alpha only")
            errors = True
        if len(request.POST['lname']) < 2:
            messages.error(request,'Last name must be at least 2 characters!')
            errors = True
        if not request.POST['lname'].isalpha():
            messages.error(request,"Last name should be alpha only")
            errors = True
        if len(request.POST['email']) < 1:
            messages.error(request,'Email cannot be empty!')
            errors = True
        if not EMAIL_REGEX.match(request.POST['email']):
            messages.error(request,'Invalid Email Address!')
            errors = True
        if len(request.POST['pass']) < 8:
            messages.error(request,'Password should be at least 8 characters!')
            errors = True
        if request.POST['pass'] != request.POST['pass_confirm']:
            messages.error(request,'Password does not match password confirmation')
            errors = True
        #validate that email doesn't already exist in database
        user = User.objects.filter(email=request.POST['email'])
        if len(user) != 0:
            messages.error(request,"This email has already been registered")
            errors = True

        return errors


        #END validation code here
        ###########################################################

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)   
    objects = UserManager()
    def __repr__(self):
        return "<User object: {} {}>".format(self.first_name,self.last_name)

class Message(models.Model):
    message = models.TextField()
    user = models.ForeignKey(User, related_name='messages')
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class Comment(models.Model):
    comment = models.TextField()
    user = models.ForeignKey(User, related_name='u_comments')
    message = models.ForeignKey(Message, related_name='m_comments')
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
