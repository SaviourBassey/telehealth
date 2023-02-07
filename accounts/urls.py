from django.urls import path
from .views import register, login_view, logout_view, dashboard, generate_key, encrypt, decrypt,f5_encrypt, receiving_keys,sending_keys, messages

app_name = "accounts"

urlpatterns = [
    path("register/", register, name="register"),
    path("dashboard/", dashboard, name="dashboard"),
    path("messages/", messages, name="messages"),
    path("generate-keys/", generate_key, name="generate-key"),
    path("encrypt/", encrypt, name="encrypt"),
    path("f5-encrypt/", f5_encrypt, name="f5-encrypt"),
    path("decrypt/", decrypt, name="decrypt"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("receiving-keys/", receiving_keys, name="receiving-keys"),
    path("sending-keys/", sending_keys, name="sending-keys")
]