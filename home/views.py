from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

@csrf_exempt
def homepage(request):
    return JsonResponse({"message": "Welcome to the Homepage!"})