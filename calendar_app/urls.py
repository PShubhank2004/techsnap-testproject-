'''from django.urls import path, include
from .views import GoogleLoginRedirect, GoogleLoginCallback
from .views import GoogleLoginRedirect, GoogleLoginCallback, FetchCalendarEvents,CreateEventForMultipleUsers, UpdateEventForMultipleUsers, DeleteEventForMultipleUsers

urlpatterns = [
    path('auth/login/', GoogleLoginRedirect, name='google-login'),
    path('auth/google/callback/', GoogleLoginCallback, name='google-callback'),
    path('calendar/events/', FetchCalendarEvents, name='fetch-events'),  
    path('calendar/create-event/', CreateEventForMultipleUsers, name='create-event'),
    path('calendar/update-event/', UpdateEventForMultipleUsers, name='update-event'),
    path('calendar/delete-event/', DeleteEventForMultipleUsers, name='delete-event'), 
]

'''


from django.urls import path
from .views import (
    GoogleLoginRedirect,
    GoogleLoginCallback,
    FetchCalendarEvents,
    BulkCreateEvents,
    BulkUpdateEvents,
    BulkDeleteEvents,
)

urlpatterns = [
    path('auth/login/', GoogleLoginRedirect, name='google-login'),
    path('auth/google/callback/', GoogleLoginCallback, name='google-callback'),
    path('calendar/events/', FetchCalendarEvents, name='fetch-events'),
    path('calendar/create-event/', BulkCreateEvents, name='bulk-create-event'),
    path('calendar/update-event/', BulkUpdateEvents, name='bulk-update-event'),
    path('calendar/delete-event/', BulkDeleteEvents, name='bulk-delete-event'),
]
