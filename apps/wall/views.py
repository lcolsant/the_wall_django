# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from .models import User
from .models import UserManager
from .models import Message
from .models import Comment
import bcrypt

def index(request):
  
    if 'id' in request.session.keys():
        return redirect('/success')
    
    return render(request,'wall/index.html')

def register(request):
    #validate data first
    errors = User.objects.validate(request)
    if (errors):
        print 'Invalid input'
        return redirect('/')
    else:
        #hash password and add to db
        hash_password = bcrypt.hashpw(request.POST['pass'].encode(), bcrypt.gensalt())
        print hash_password
        User.objects.create(first_name=request.POST['fname'],last_name=request.POST['lname'],email=request.POST['email'],password=hash_password)
        user = User.objects.filter(email=request.POST['email'])
        request.session['id'] = user[0].id
    return redirect('/success')

def login(request):
    email = request.POST['email']
    password = request.POST['pass']
    user = User.objects.filter(email=email)
    if len(user) == 0:
        messages.error(request,"User not recognized")
        return redirect('/')
    else:
        if ( bcrypt.checkpw(password.encode(), user[0].password.encode()) ):
            print 'password matches'
            request.session['id'] = user[0].id
            return redirect('/success')
        else:
            messages.error(request,'Invalid password.')
            return redirect('/')


def success(request):
    context = {
        'user':User.objects.get(id=request.session['id']),
        'post_data':Message.objects.all(),
        'comment_data':Comment.objects.all(),
    }
    
    return render(request, 'wall/success.html',context)

#@app.route('/message',methods=['POST'])
def add_message(request):
    #message = request.POST['message']
    #print 'new message:', message
    Message.objects.create(message=request.POST['add_message'], user=User.objects.get(id=request.session['id']))
    messages.success(request,'Message posted successfully.')

    return redirect('/')

#@app.route('/message/delete/<id>')
def delete_message(request,id):
    m = Message.objects.get(id=id)
    m.delete()
    return redirect('/success')    

#@app.route('/comment',methods=['POST'])
def comment(request):
    Comment.objects.create(comment=request.POST['comment'],user=User.objects.get(id=request.session['id']),message=Message.objects.get(id=request.POST['message_ID']) )
    return redirect('/success')    


def logout(request):
    request.session.clear()
    return redirect('/')