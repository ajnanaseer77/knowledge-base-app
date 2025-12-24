
from django.urls import path
from .views import (
    CreateNoteView,UpdateNoteView,login_user,register_user,
    ListNotesView, ViewNoteView, DeleteNoteView,
    AssignCategoryView, CreateCategoryView,
    SearchNotesView,ToggleFavoriteView,refresh_access_token
)

app_name = "register"

urlpatterns = [
    
    path('register/', register_user, name='register'),
    path('login/', login_user, name='login'),
    path("token/refresh/", refresh_access_token,name="refrsh_token"),
    path('api/notes/create/', CreateNoteView.as_view(), name='create_note'),
    path('api/notes/update/<int:pk>/', UpdateNoteView.as_view()),
    path('api/notes/delete/<int:pk>/', DeleteNoteView.as_view()),
    path('api/notes/', ListNotesView.as_view(), name='notes_list'),
    path('api/notes/<int:pk>/', ViewNoteView.as_view(), name='view_note'),
    path('api/categories/create/', CreateCategoryView.as_view(), name='create_category'),
    path('api/notes/<int:note_id>/assign-category/', AssignCategoryView.as_view(), name='assign_category'),
    path('api/notes/search/', SearchNotesView.as_view(), name='search_notes'),
    path('api/notes/<int:pk>/toggle-favorite/', ToggleFavoriteView.as_view(), name='toggle_favorite'),
    

]
