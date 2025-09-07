from django.urls import path
from . import views

urlpatterns = [
    path("", views.homepage, name="homepage"),    # http://127.0.0.1:8000/
]