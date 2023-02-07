from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import rsa
import numpy as np
from PIL import Image  
import PIL 
from .models import Key, Message
from .main import encode_enc
import os
from django.conf import settings

# Create your views here.

def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        if User.objects.filter(email=email).exists():
            message = "The email is already registered"
            return redirect("accounts:register")
        else:
            new_user = User.objects.create_user(username=username, email=email, password=password)
            new_user.save()
            return redirect("accounts:login")
    return render(request, "accounts/register.html")

def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        if User.objects.filter(email=email).exists():
            fetch_user = User.objects.filter(email=email).first()
            username = fetch_user.username
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages = f"Welcome back {username}"
                return redirect("accounts:dashboard")
            else:
                print("not finally")
                message = "Incorrect credentials "
                return redirect("accounts:login")
    return render(request, "accounts/login.html")

def logout_view(request):
    logout(request)
    message = "You've logged out"
    return redirect("home:home")


@login_required
def dashboard(request):
    return render(request, "accounts/dashboard.html")


@login_required
def messages(request):
    if Message.objects.filter(key__destination_email=request.user.email).exists():
        all_messages = Message.objects.filter(key__destination_email=request.user.email).order_by("-timestamp")
    else:
        all_messages = None
    context = {
        "all_messages":all_messages
    }
    return render(request, "accounts/messages.html", context)


@login_required
def receiving_keys(request):
    email = request.user.email
    if Key.objects.filter(destination_email=email).exists():
        receiving_user_records = Key.objects.filter(destination_email=email).order_by("-timestamp")
    else:
        receiving_user_records = None
    context = {
        "receiving_user_records": receiving_user_records
    }
    return render(request, "accounts/receiving-keys.html", context)


@login_required
def sending_keys(request):
    user = request.user
    if Key.objects.filter(user=user).exists():
        sending_user_records = Key.objects.filter(user=user).order_by("-timestamp")
    else:
        sending_user_records = None
    context = {
        "sending_user_records": sending_user_records
    }
    return render(request, "accounts/sending-keys.html", context)


@login_required
def generate_key(request):
    if request.method == "POST":
        email = request.POST.get("destination_email")
        user_email = request.user.email
        print(user_email)
        print(email)
        if email != user_email:
            if User.objects.filter(email=email).exists(): #check if the destination email exits in our  Users table database
                if Key.objects.filter(destination_email=email).exists(): #check if destination email exists already in the keys table 
                    message = "You already have a key associated the this email"
                    return redirect("accounts:generate-key")
                else:
                    key_length = int(request.POST.get("key_length"))
                    steg_key1 = int(request.POST.get("steg-key1"))
                    steg_key2 = int(request.POST.get("steg-key2"))
                    steg_key3 = int(request.POST.get("steg-key3"))
                    steg_key4 = int(request.POST.get("steg-key4"))
                    steg_key5 = int(request.POST.get("steg-key5"))
                    steg_key6 = int(request.POST.get("steg-key6"))
                    steg_key7 = int(request.POST.get("steg-key7"))
                    steg_key8 = int(request.POST.get("steg-key8"))
                    steg_key9 = int(request.POST.get("steg-key9"))
                    if key_length >= 1024:
                        n_array = np.array([[steg_key1, steg_key2, steg_key3],[steg_key4, steg_key5, steg_key6],[steg_key7, steg_key8, steg_key9]])
                        det = np.linalg.det(n_array)
                        matrix_key = int((det))
                        steg_order = f"{steg_key1}-{steg_key2}-{steg_key3}-{steg_key4}-{steg_key5}-{steg_key6}-{steg_key7}-{steg_key8}-{steg_key9}"
                        (publicKey, privateKey) = rsa.newkeys(key_length)

                        new_key = Key(user=request.user, destination_email=email, public_key="public_key.pem", private_key="private_key.pem", f5_order="f5.txt", matrix_key=matrix_key)

                        new_key.f5_order.name = f"/f5/f5_order_from_{request.user.username}_to_{email}.txt"
                        new_path_f5 = settings.MEDIA_ROOT + new_key.f5_order.name
                        new_key.public_key.name = f"/keys/public_keys/publicKey_from_{request.user.username}_to_{email}.pem"
                        new_path_public = settings.MEDIA_ROOT + new_key.public_key.name
                        new_key.private_key.name = f"/keys/private_keys/privateKey_from_{request.user.username}_to_{email}.pem"
                        new_path_private = settings.MEDIA_ROOT + new_key.private_key.name
                      
                        with  open(str(new_path_f5), 'w') as f:
                            f.write(steg_order)
                            f.close()
                        with  open(str(new_path_public), 'wb') as p:
                            p.write(publicKey.save_pkcs1('PEM'))
                            f.close()
                        with  open(str(new_path_private), 'wb') as p:
                            p.write(privateKey.save_pkcs1('PEM'))
                            f.close()
                        new_key.save()
                        context = {
                            "public_key": publicKey,
                            "steg_key1":steg_key1,
                            "steg_key2":steg_key2,
                            "steg_key3":steg_key3,
                            "steg_key4":steg_key4,
                            "steg_key5":steg_key5,
                            "steg_key6":steg_key6,
                            "steg_key7":steg_key7,
                            "steg_key8":steg_key8,
                            "steg_key9":steg_key9,
                            "email":email,
                            "key_length":key_length
                        }
                        return render(request, "accounts/generate-key.html", context)
                    else:
                        message = "Key length must be greater than or equals 1024 "
                        return redirect("accounts:generate-key")
                        
            else:
                message = "This email is not reg+istered on our database"
                return redirect("accounts:generate-key")

        else:
            message = "Can't generate key to your email"
            return redirect("accounts:generate-key")

    return render(request, "accounts/generate-key.html")


@login_required
def encrypt(request):
    if request.method == "POST":
        destination_email = request.POST.get("email")
        message = request.POST.get("message")
        public_key_url = f"/keys/public_keys/publicKey_from_{request.user.username}_to_{destination_email}.pem"
        new_path_public = settings.MEDIA_ROOT + public_key_url
        destination_email_url = f"/f5/f5_order_from_{request.user.username}_to_{destination_email}.txt"
        new_path_destination_email = settings.MEDIA_ROOT + destination_email_url
        try:
            with open(str(new_path_public), 'rb') as p:
                publicKey = rsa.PublicKey.load_pkcs1(p.read())
                print(publicKey)
            f = open( str(new_path_destination_email), "r")
        except:
            message = "No public key matching the specified email"
            return redirect("accounts:encrypt")
        else:
            ciphertext = rsa.encrypt(message.encode('ascii'), publicKey)
            print(ciphertext)

            context = {
                "ciphertext":ciphertext,
                "destination_email":destination_email,
                "message":message,
            }
            return render(request, "accounts/encrypt.html", context)

    return render(request, "accounts/encrypt.html")


@login_required
def f5_encrypt(request):
    if request.method == "POST" and request.FILES['image-file']:
        cipher_text = request.POST.get("cipher-text")
        message = request.POST.get("message")
        destination_email = request.POST.get("email")
        image_file = request.FILES.get("image-file")
        picture = Image.open(image_file, "r")
        newimg = picture.copy()
        encode_enc(newimg, cipher_text)
        key = Key.objects.get(user=request.user, destination_email=destination_email)
        new_message = Message(key=key, message=message, cipher_text=cipher_text)
        new_message.save()
        img_location = f"encrypted_images/from_{request.user.username}_image{new_message.id}.png"
        new_message.image = img_location
        new_message.save()
        new_image_url = f"/encrypted_images/from_{request.user.username}_image{new_message.id}.png"
        new_path_image = settings.MEDIA_ROOT + new_image_url
        newimg.save(str(new_path_image))
        return redirect("home:home")
        

@login_required
def decrypt(request):
    if request.method == "POST" and request.FILES['image-file']:
        image_file = str(request.FILES.get("image-file"))
        steg_key1 = int(request.POST.get("steg-key1"))
        steg_key2 = int(request.POST.get("steg-key2"))
        steg_key3 = int(request.POST.get("steg-key3"))
        steg_key4 = int(request.POST.get("steg-key4"))
        steg_key5 = int(request.POST.get("steg-key5"))
        steg_key6 = int(request.POST.get("steg-key6"))
        steg_key7 = int(request.POST.get("steg-key7"))
        steg_key8 = int(request.POST.get("steg-key8"))
        steg_key9 = int(request.POST.get("steg-key9"))
        # get user email from the frontend and replace the user_email
        user_email = "slyde619@gmail.com"
        #to_user_key_record = Key.objects.get(destination_email=user_email)
        n_array = np.array([[steg_key1, steg_key2, steg_key3],[steg_key4, steg_key5, steg_key6],[steg_key7, steg_key8, steg_key9]])
        det = np.linalg.det(n_array)
        matrix_key = int((det))
        if Key.objects.filter(matrix_key=matrix_key, destination_email=user_email).exists():
            img_location = f"encrypted_images/{image_file}"
            new_image = Message()
            new_image.image = img_location
            all_messages = Message.objects.all()
            for item in all_messages:
                if new_image.image.name == item.image.name:
                    image_exist = True
                else:
                    image_exist = False

            if image_exist == True:
                get_message = Message.objects.get(image=new_image.image)
                cipher_text = get_message.cipher_text
                message = get_message.message
                context = {
                    "cipher_text":cipher_text,
                    "message":message,
                    "image_file":image_file,
                    "steg_key1":steg_key1,
                    "steg_key2":steg_key2,
                    "steg_key3":steg_key3,
                    "steg_key4":steg_key4,
                    "steg_key5":steg_key5,
                    "steg_key6":steg_key6,
                    "steg_key7":steg_key7,
                    "steg_key8":steg_key8,
                    "steg_key9":steg_key9,
                }
                return render(request, "accounts/decrypt.html", context)

            else:
                get_message = "No hidden data"
                return redirect("accounts:decrypt")
            
        else:
            message = "You have not been associated with any private key"
            print(message)


    # def decrypt(ciphertext, key):
    # try:
    #     return rsa.decrypt(ciphertext, key).decode('ascii')
    # except:
    #     return False
    return render(request, "accounts/decrypt.html")