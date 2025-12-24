import jwt
import json
from datetime import datetime, timedelta
from functools import wraps

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q

from .models import Note, Category

User = get_user_model()
def generate_access_token(user):
    payload = {
        "user_id": user.id,
        "type": "access",
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def generate_refresh_token(user):
    payload = {
        "user_id": user.id,
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_jwt(token):
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def jwt_token_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header.replace("Bearer ", "")

        if not token:
            return JsonResponse({"error": "Access token required"}, status=401)

        payload = decode_jwt(token)

        if not payload or payload.get("type") != "access":
            return JsonResponse({"error": "Invalid or expired access token"}, status=401)

        try:
            request.user = User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=401)

        return view_func(request, *args, **kwargs)

    return wrapper


@csrf_exempt
def register_user(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST request required"}, status=405)

    data = json.loads(request.body)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return JsonResponse({"error": "Username and password required"}, status=400)

    if User.objects.filter(username=username).exists():
        return JsonResponse({"error": "Username already exists"}, status=400)

    User.objects.create_user(username=username, password=password)
    return JsonResponse({"message": "User registered successfully"})

@csrf_exempt
def login_user(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST request required"}, status=405)

    data = json.loads(request.body)
    user = authenticate(
        username=data.get("username"),
        password=data.get("password")
    )

    if not user:
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    return JsonResponse({
        "access_token": generate_access_token(user),
        "refresh_token": generate_refresh_token(user)
    })

@csrf_exempt
def refresh_access_token(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST request required"}, status=405)

    data = json.loads(request.body)
    refresh_token = data.get("refresh_token")

    if not refresh_token:
        return JsonResponse({"error": "Refresh token required"}, status=400)

    payload = decode_jwt(refresh_token)

    if not payload or payload.get("type") != "refresh":
        return JsonResponse({"error": "Invalid or expired refresh token"}, status=401)

    try:
        user = User.objects.get(id=payload["user_id"])
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=401)

    return JsonResponse({
        "access_token": generate_access_token(user)
    })






@method_decorator(csrf_exempt, name="dispatch")
class CreateNoteView(View):
    @method_decorator(jwt_token_required)
    def post(self, request):
        data = json.loads(request.body)
        note = Note.objects.create(
            title=data.get("title"),
            content=data.get("content"),
            user=request.user
        )
        return JsonResponse({"message": "Note created", "id": note.id}, status=201)

@method_decorator(csrf_exempt, name="dispatch")
class UpdateNoteView(View):
    @method_decorator(jwt_token_required)
    def put(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)
        data = json.loads(request.body)
        note.title = data.get("title", note.title)
        note.content = data.get("content", note.content)
        note.save()
        return JsonResponse({"message": "Note updated"})

@method_decorator(csrf_exempt, name="dispatch")
class DeleteNoteView(View):
    @method_decorator(jwt_token_required)
    def delete(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)
        note.delete()
        return JsonResponse({"message": "Note deleted"})

class ListNotesView(View):
    @method_decorator(jwt_token_required)
    def get(self, request):
        notes = [
            {
                "id": n.id,
                "title": n.title,
                "content": n.content,
                "category": n.category.name if n.category else None,
                "is_favorite": n.is_favorite
            }
            for n in Note.objects.filter(user=request.user)
        ]
        return JsonResponse(notes, safe=False)

class ViewNoteView(View):
    @method_decorator(jwt_token_required)
    def get(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)
        return JsonResponse({
            "id": note.id,
            "title": note.title,
            "content": note.content,
            "category": note.category.name if note.category else None,
            "is_favorite": note.is_favorite
        })


@method_decorator(csrf_exempt, name="dispatch")
class CreateCategoryView(View):
    @method_decorator(jwt_token_required)
    def post(self, request):
        data = json.loads(request.body)
        category = Category.objects.create(
            name=data.get("name"),
            user=request.user
        )
        return JsonResponse({"message": "Category created", "id": category.id})

@method_decorator(csrf_exempt, name="dispatch")
class AssignCategoryView(View):
    @method_decorator(jwt_token_required)
    def put(self, request, note_id):
        data = json.loads(request.body)
        note = Note.objects.filter(id=note_id, user=request.user).first()
        category = Category.objects.filter(id=data.get("category_id"), user=request.user).first()
        if not note or not category:
            return JsonResponse({"error": "Invalid note or category"}, status=404)
        note.category = category
        note.save()
        return JsonResponse({"message": "Category assigned"})


@method_decorator(csrf_exempt, name="dispatch")
class ToggleFavoriteView(View):
    @method_decorator(jwt_token_required)
    def post(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)
        note.is_favorite = not note.is_favorite
        note.save()
        return JsonResponse({"favorite": note.is_favorite})


class SearchNotesView(View):
    @method_decorator(jwt_token_required)
    def get(self, request):
        q = request.GET.get("q", "")
        notes = Note.objects.filter(user=request.user).filter(
            Q(title__icontains=q) |
            Q(content__icontains=q) |
            Q(category__name__icontains=q)
        )
        return JsonResponse(
            [{"id": n.id, "title": n.title, "content": n.content} for n in notes],
            safe=False
        )
