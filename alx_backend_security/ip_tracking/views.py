from django.shortcuts import render
from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.contrib.auth.decorators import login_required

# Create your views here.
@ratelimit(key="ip", rate="5/m", block=True)
def anonymous_sensitive_view(request):
    return JsonResponse({"message": "Anonymous sensitive view accessed"})


@ratelimit(key="ip", rate="10/m", block=True)
@login_required
def authenticated_sensitive_view(request):
    return JsonResponse({"message": "Authenticated sensitive view accessed"})



