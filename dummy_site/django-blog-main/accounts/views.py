from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegistrationForm, ProfileUdpateForm, UserUpdateForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate,login
from feature.models import Post

def register(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(request, username=username, password=raw_password)
            if user is not None:
                login(request, user)
                messages.success(request, "Account created successfully!")
                return redirect('feature-home')
            
        else:
            # Check for specific field errors
            if form.errors.get('username'):
                messages.error(request, "Username already exists or is invalid.")
            elif form.errors.get('password1'):
                error_msg = form.errors['password1'][0]
                messages.error(request, f"Password Error: {error_msg}")
            elif form.errors.get('password2'):
                error_msg = form.errors['password2'][0]
                messages.error(request, f"Password Match Error: {error_msg}")
            elif form.non_field_errors():
                messages.error(request, "Something went wrong — please review your input.")
            else:
                messages.error(request, "Please check your input and try again.")
    else:
        form = UserRegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})

@login_required
def profile(request):
    if request.method == "POST":
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = ProfileUdpateForm(request.POST, request.FILES, instance=request.user.profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, "Your profile has been updated!")
            return redirect('auth-profile')    
    else:
        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileUdpateForm(instance=request.user.profile)

    user_posts = Post.objects.filter(author=request.user).order_by('-date_posted')
    
    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'user_posts': user_posts
    }
    
    return render(request, 'accounts/profile.html', context)