from django.urls import path
from .views import (
    register_user,
    login_user,
    refresh_access_token,
    assign_permission,
    CreateNoteView,
    UpdateNoteView,
    DeleteNoteView,
    ListNotesView,
    CreateCategoryView,
    AssignCategoryView,
    AdminViewAllUsersView,
    AdminDeleteUserView,
    AdminDeleteNoteView,
    ViewNoteView,
    SearchNotesView,
    ToggleFavoriteView,
)

urlpatterns = [
  
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('refresh-token/', refresh_access_token, name='refresh_access_token'),
    path('assign-permission/', assign_permission, name='assign_permission'),
    path('notes/', ListNotesView.as_view(), name='list_notes'),
    path('notes/create/', CreateNoteView.as_view(), name='create_note'),
    path('notes/update/<int:note_id>/', UpdateNoteView.as_view(), name='update_note'),
    path('notes/delete/<int:note_id>/', DeleteNoteView.as_view(), name='delete_note'),
    path('categories/create/', CreateCategoryView.as_view(), name='create_category'),
    path('categories/assign/<int:note_id>/', AssignCategoryView.as_view(), name='assign_category'),
    path('admin1/users/', AdminViewAllUsersView.as_view(), name='admin_view_users'),
    path('admin1/users/delete/<int:user_id>/', AdminDeleteUserView.as_view(), name='admin_delete_user'),
    path('admin1/notes/delete/<int:note_id>/', AdminDeleteNoteView.as_view(), name='admin_delete_note'),
    path("notes/<int:note_id>/", ViewNoteView.as_view()),
    path("notes/search/", SearchNotesView.as_view()),
    path("notes/<int:note_id>/favorite/", ToggleFavoriteView.as_view()),
]
