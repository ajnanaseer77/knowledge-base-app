import jwt, json
from datetime import datetime, timedelta
from functools import wraps

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Q
from .models import Note, Category

User = get_user_model()

def json_error(message, status):
    return JsonResponse({"error": message}, status=status)

def get_note_or_403(note_id, user):
    note = Note.objects.filter(id=note_id).first()
    if not note:
        return None, json_error("Note not found", 404)
    if note.user != user:
        return None, json_error("You do not have permission to access this note", 403)
    return note, None

def create_token(user, token_type):
    expiry = timedelta(minutes=15) if token_type=="access" else timedelta(days=7)
    payload = {"user_id": user.id, "type": token_type, "exp": datetime.utcnow() + expiry}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None

def jwt_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.META.get("HTTP_AUTHORIZATION", "").replace("Bearer ","")
        if not token:
            return json_error("Access token required", 401)
        payload = decode_token(token)
        if not payload or payload.get("type") != "access":
            return json_error("Invalid or expired access token", 401)
        user = User.objects.filter(id=payload["user_id"]).first()
        if not user:
            return json_error("User not found", 401)
        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper

@csrf_exempt
def register_user(request):
    if request.method != "POST":
        return json_error("POST request required", 405)
    if not request.content_type.startswith("application/json"):
        return json_error("Content-Type must be application/json", 415)
    data = json.loads(request.body)
    if not data.get("username") or not data.get("password"):
        return json_error("Username and password required", 400)
    if User.objects.filter(username=data["username"]).exists():
        return json_error("Username already exists", 400)
    User.objects.create_user(username=data["username"], password=data["password"])
    return JsonResponse({"message":"User registered"}, status=201)

@csrf_exempt
def login_user(request):
    if request.method != "POST":
        return json_error("POST request required", 405)
    data = json.loads(request.body)
    user = authenticate(username=data.get("username"), password=data.get("password"))
    if not user:
        return json_error("Invalid credentials", 401)
    return JsonResponse({
        "access_token": create_token(user, "access"),
        "refresh_token": create_token(user, "refresh")
    })

@csrf_exempt
def refresh_access_token(request):
    data = json.loads(request.body)
    payload = decode_token(data.get("refresh_token"))
    if not payload or payload.get("type")!="refresh":
        return json_error("Invalid refresh token", 401)
    user = User.objects.filter(id=payload["user_id"]).first()
    return JsonResponse({"access_token": create_token(user, "access")})


@method_decorator(csrf_exempt, name="dispatch")
class CreateNoteView(View):
    @method_decorator(jwt_required)
    def post(self, request):
        data = json.loads(request.body)
        note = Note.objects.create(user=request.user, title=data.get("title"), content=data.get("content"))
        return JsonResponse({"id": note.id, "message":"Note created"}, status=201)

@method_decorator(csrf_exempt, name="dispatch")
class UpdateNoteView(View):

    @method_decorator(jwt_required)
    def put(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse(
                {"error": "You don't have permission to update this note"},
                status=403
            )
        data = json.loads(request.body)
        note.title = data.get("title", note.title)
        note.content = data.get("content", note.content)
        note.save()

        return JsonResponse({"message": "Note updated"})

@method_decorator(csrf_exempt, name="dispatch")
class DeleteNoteView(View):

    @method_decorator(jwt_required)
    def delete(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse(
                {"error": "You don't have permission to delete this note"},
                status=403
            )
        note.delete()
        return JsonResponse({"message": "Note deleted"})


class ViewNoteView(View):

    @method_decorator(jwt_required)
    def get(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse(
                {"error": "You don't have permission to view this note"},
                status=403
            )
        return JsonResponse({
            "id": note.id,
            "title": note.title,
            "content": note.content,
            "category": note.category.name if note.category else None,
            "is_favorite": note.is_favorite
        })


@method_decorator(csrf_exempt, name="dispatch")
class AssignCategoryView(View):

    @method_decorator(jwt_required)
    def put(self, request, note_id):
        note = Note.objects.filter(id=note_id, user=request.user).first()
        if not note:
            return JsonResponse(
                {"error": "You don't have permission to assign category to this note"},
                status=403
            )

        data = json.loads(request.body)
        category = Category.objects.filter(id=data.get("category_id"), user=request.user).first()
        if not category:
            return JsonResponse({"error": "Category not found"}, status=404)

        note.category = category
        note.save()
        return JsonResponse({"message": "Category assigned"})


@method_decorator(csrf_exempt, name="dispatch")
class ToggleFavoriteView(View):

    @method_decorator(jwt_required)
    def post(self, request, pk):
        note = Note.objects.filter(id=pk, user=request.user).first()
        if not note:
            return JsonResponse(
                {"error": "You don't have permission to change favorite for this note"},
                status=403
            )

        note.is_favorite = not note.is_favorite
        note.save()
        return JsonResponse({"favorite": note.is_favorite})



class ListNotesView(View):
    @method_decorator(jwt_required)
    def get(self, request):
        notes = Note.objects.filter(user=request.user)
        data = [
            {
                "id": n.id,
                "title": n.title,
                "content": n.content,
                "category": n.category.name if n.category else None,
                "is_favorite": n.is_favorite
            } 
            for n in notes
        ]
        return JsonResponse(data, safe=False)

@method_decorator(csrf_exempt, name="dispatch")
class CreateCategoryView(View):
    @method_decorator(jwt_required)
    def post(self, request):
        data = json.loads(request.body)
        category = Category.objects.create(user=request.user, **data)
        return JsonResponse({"id": category.id, "message":"Category created"})



class SearchNotesView(View):
    @method_decorator(jwt_required)
    def get(self, request):
        q = request.GET.get("q","")
        notes = Note.objects.filter(user=request.user).filter(
            Q(title__icontains=q) | Q(content__icontains=q) | Q(category__name__icontains=q)
        )
        return JsonResponse(list(notes.values("id","title","content")), safe=False)
