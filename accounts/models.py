from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Key(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    destination_email = models.EmailField(null=True, blank=True)
    public_key = models.FileField(upload_to="keys/public_keys")
    private_key = models.FileField(upload_to="keys/private_keys")
    f5_order = models.FileField(upload_to="f5")
    matrix_key = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} keys for {self.destination_email}"


class Message(models.Model):
    key = models.ForeignKey(Key, on_delete=models.CASCADE, null=True, blank=True)
    image = models.ImageField(upload_to="encrypted_images", null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    cipher_text = models.TextField(null=True)
    timestamp = models.DateTimeField(auto_now_add=True)