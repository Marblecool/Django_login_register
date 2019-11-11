from django.shortcuts import render
from django.shortcuts import redirect
from . import models
from . import forms
import hashlib


# Create your views here.
def hash_code(s, salt='login_register'):  # 加点盐
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())  # update方法只接收bytes类型
    return h.hexdigest()


def index(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    return render(request, 'login/index.html')


def login(request):
    if request.method == 'POST':
        # username = request.POST.get('username')
        #     password = request.POST.get('password')
        #     message = '请检查输入内容'
        #     # 通过strip方法，将用户名前后无效的空格剪除；
        #     if username.strip() and password:
        #         # 使用try异常机制，防止数据库查询失败的异常
        #         try:
        #             user = models.User.objects.get(name=username)
        #         except:
        #             message = '用户不存在'
        #             return render(request, 'login/login.html', {'message': message})
        #         if user.password == password:
        #             return redirect('/index/')
        #         else:
        #             message = '密码输入错误'
        #             return render(request, 'login/login.html', {'message': message})
        #     else:
        #         return render(request, 'login/login.html', {'message': message})
        # return render(request, 'login/login.html')

        # 不允许重复登录
        if request.session.get('is_login', None):
            return redirect('/index/')

        login_form = forms.UserForm(request.POST)
        message = '请检查输入内容'
        if login_form.is_valid():
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')

            try:
                user = models.User.objects.get(name=username)
            except:
                message = '用户不存在'
                return render(request, 'login/login.html', locals())

            if user.password == hash_code(password):
                # 往session字典内写入用户状态和数据
                request.session['is_login'] = True
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                return redirect('/index/')
            else:
                message = '密码输入错误'
                return render(request, 'login/login.html', locals())
        else:
            return render(request, 'login/login.html', locals())

    login_form = forms.UserForm()
    return render(request, 'login/login.html', locals())


def register(request):
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        register_form = forms.RegisterForm(request.POST)
        message = "请检查输入的内容"
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            sex = register_form.cleaned_data.get('sex')

            if password1 != password2:
                message = '两次输入的密码不一致'
                return render(request, 'login/register.html', {'message': message, 'register_form': register_form})
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:
                    message = '用户名已存在'
                    return render(request, 'login/register.html', {'message': message, 'register_form': register_form})
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:
                    message = '邮箱已被注册'
                    return render(request, 'login/register.html', {'message': message, 'register_form': register_form})

                new_user = models.User()
                new_user.name = username
                new_user.password = hash_code(password1)
                new_user.email = email
                new_user.sex = sex
                new_user.save()

                return redirect('/login/')
        else:
            return render(request, 'login/register.html', {'message': message, 'register_form': register_form})
    register_form = forms.RegisterForm()
    return render(request, 'login/register.html', locals())


def logout(request):
    if not request.session.get('is_login', None):
        # 如果本来就未登录，也就没有登出一说
        return redirect("/login/")
    request.session.flush()
    # 或者使用下面的方法
    # del request.session['is_login']
    # del request.session['user_id']
    # del request.session['user_name']
    return redirect("/login/")
