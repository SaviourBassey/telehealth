from django.shortcuts import render
from accounts.models import Key

# Create your views here.

def home(request):
    key = Key.objects.all().order_by("-timestamp")[0]
    return render(request, "home/index.html", {"key":key})