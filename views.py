from django.shortcuts import redirect
from django.conf import settings
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import GoogleOAuthToken
import requests
from datetime import datetime, timedelta
from django.utils.timezone import now
from django.contrib.auth import get_user_model, login
from django.utils import timezone
import pytz
from django.contrib.auth.backends import ModelBackend  

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
EVENTS_URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events"

def get_user_tokens(user_id):
    """ Fetch user token from the database """
    return GoogleOAuthToken.objects.filter(user_id=user_id).first()

def update_or_create_token(user_id, access_token, refresh_token, expires_in):
    """ Store or update user tokens in the database """
    expires_at = datetime.now() + timedelta(seconds=expires_in)
    GoogleOAuthToken.objects.update_or_create(
        user_id=user_id,
        defaults={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
        },
    )

def refresh_access_token(user_id):
    """ Refresh access token if expired """
    token = get_user_tokens(user_id)
    if not token or not token.refresh_token:
        return None

    data = {
        "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
        "client_secret": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
        "refresh_token": token.refresh_token,
        "grant_type": "refresh_token",
    }

    response = requests.post(TOKEN_URL, data=data)
    token_info = response.json()
    new_access_token = token_info.get("access_token")

    if new_access_token:
        update_or_create_token(user_id, new_access_token, token.refresh_token, token_info.get("expires_in", 3600))
        return new_access_token

    return None

def get_valid_access_token(user_id):
    try:
        token = GoogleOAuthToken.objects.get(user_id=user_id)
        
        # Ensure expires_at is timezone-aware
        if token.expires_at and token.expires_at.tzinfo is None:
            token.expires_at = token.expires_at.replace(tzinfo=pytz.UTC)

        # Compare with timezone-aware datetime
        if token.expires_at < timezone.now():  
            new_access_token = refresh_access_token(user_id)  # Get only access token string

            if new_access_token:  # If refresh was successful, update the token
                token.access_token = new_access_token
                token.expires_at = timezone.now() + timedelta(seconds=3600)  # Update expiry
                token.save()

            else:
                return None  # Refresh failed

        return token.access_token  # Return the latest valid access token

    except GoogleOAuthToken.DoesNotExist:
        return None



@api_view(["GET"])
def GoogleLoginRedirect(request):
    """ Redirect user to Google's OAuth login page """
    params = {
        "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
        "redirect_uri": settings.SOCIAL_AUTH_GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE),
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = f"{GOOGLE_AUTH_URL}?{'&'.join([f'{key}={value}' for key, value in params.items()])}"
    return redirect(auth_url)



#User = get_user_model()

#TOKEN_URL = "https://oauth2.googleapis.com/token"
USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"




User = get_user_model()

@api_view(["GET"])
def GoogleLoginCallback(request):
    """ Handles Google OAuth callback and stores token in DB """
    code = request.GET.get("code")
    if not code:
        return Response({"error": "No authorization code provided"}, status=400)

    # Exchange code for access token
    data = {
        "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
        "client_secret": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
        "code": code,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    response = requests.post("https://oauth2.googleapis.com/token", data=data)
    token_info = response.json()

    if "access_token" not in token_info:
        return Response({"error": "Failed to get access token"}, status=400)

    access_token = token_info["access_token"]
    refresh_token = token_info.get("refresh_token", "")
    expires_in = token_info["expires_in"]

    # Fetch user info from Google
    headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers)
    user_info = user_info_response.json()

    if "email" not in user_info:
        return Response({"error": "Failed to fetch user information"}, status=400)

    email = user_info["email"]
    
    # Find or create user
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={"username": email, "first_name": user_info.get("given_name", "")}
    )

    # 🔹 Explicitly set the authentication backend
    user.backend = "django.contrib.auth.backends.ModelBackend"

    # 🔹 Log the user in
    login(request, user, backend=user.backend)  

    # Store token
    GoogleOAuthToken.objects.update_or_create(
        user=user,
        defaults={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": now() + timedelta(seconds=expires_in),
        },
    )

    return Response({"message": "Google authentication successful", "user": email})


from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes

@api_view(["GET"])
@permission_classes([IsAuthenticated])  # ✅ Ensure user is logged in
def FetchCalendarEvents(request):
    user = request.user
    if not user.is_authenticated:
        return Response({"error": "Unauthorized. Please log in."}, status=401)

    # Now user is authenticated, fetch events
    token = GoogleOAuthToken.objects.filter(user=user).first()
    if not token:
        return Response({"error": "No Google token found for user"}, status=400)

    access_token = token.access_token
    headers = {"Authorization": f"Bearer {access_token}"}

    # Call Google Calendar API
    response = requests.get("https://www.googleapis.com/calendar/v3/calendars/primary/events", headers=headers)
    
    if response.status_code != 200:
        return Response({"error": "Failed to fetch events", "details": response.json()}, status=response.status_code)

    return Response(response.json(), status=200)

EVENTS_URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events"

@api_view(["POST"])
def BulkCreateEvents(request):
    """ Bulk create calendar events only for users who have granted permissions """
    users = GoogleOAuthToken.objects.exclude(refresh_token__isnull=True).exclude(refresh_token="")
    event_data = request.data.get("events", [])

    if not event_data:
        return Response({"error": "No events provided"}, status=400)

    results = []
    for user in users:
        access_token = get_valid_access_token(user.user_id)
        if not access_token:
            continue

        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

        for event in event_data:
            start_time = datetime.fromisoformat(event["start"]).astimezone(pytz.timezone("Asia/Kolkata"))
            end_time = datetime.fromisoformat(event["end"]).astimezone(pytz.timezone("Asia/Kolkata"))

            event_body = {
                "summary": event.get("summary", "Untitled Event"),
                "description": event.get("description", ""),
                "start": {"dateTime": start_time.isoformat(), "timeZone": "Asia/Kolkata"},
                "end": {"dateTime": end_time.isoformat(), "timeZone": "Asia/Kolkata"},
                "location": event.get("location", ""),
            }

            response = requests.post(EVENTS_URL, headers=headers, json=event_body)
            results.append({"user_id": user.user_id, "status": response.status_code, "response": response.json()})

    return Response(results)

@api_view(["PUT"])
def BulkUpdateEvents(request):
    """ Bulk update events only for users with valid permissions """
    users = GoogleOAuthToken.objects.exclude(refresh_token__isnull=True).exclude(refresh_token="")
    event_data = request.data

    results = []
    for user in users:
        access_token = get_valid_access_token(user.user_id)
        if not access_token:
            continue

        event_id = event_data.get("event_id")
        if not event_id:
            continue

        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        response = requests.put(f"{EVENTS_URL}/{event_id}", headers=headers, json=event_data)

        results.append({"user_id": user.user_id, "status": response.status_code, "response": response.json()})

    return Response(results)

@api_view(["DELETE"])
def BulkDeleteEvents(request):
    """ Bulk delete events only for users with valid permissions """
    users = GoogleOAuthToken.objects.exclude(refresh_token__isnull=True).exclude(refresh_token="")
    event_id = request.data.get("event_id")

    results = []
    for user in users:
        access_token = get_valid_access_token(user.user_id)
        if not access_token:
            continue

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.delete(f"{EVENTS_URL}/{event_id}", headers=headers)

        results.append({"user_id": user.user_id, "status": response.status_code})

    return Response(results)
