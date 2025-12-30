import jwt, json
from datetime import datetime, timedelta
from functools import wraps

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Permission
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Q

from .models import Note, Category

User = get_user_model()



def json_error(message, status):
    return JsonResponse({"error": message}, status=status)


def create_token(user, token_type):
    expiry = timedelta(minutes=15) if token_type == "access" else timedelta(days=7)
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
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Bearer "):
            return JsonResponse({"error": "Access token required"}, status=401)

        token = auth.replace("Bearer ", "")
        payload = decode_token(token)

        if not payload or payload.get("type") != "access":
            return JsonResponse({"error": "Invalid or expired token"}, status=401)

        user = User.objects.filter(id=payload.get("user_id")).first()
        if not user:
            return JsonResponse({"error": "User not found"}, status=401)

        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper

def perm_required(permission):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not hasattr(request, "user") or request.user is None:
                return JsonResponse({"error": "Authentication required"}, status=401)

           
            if hasattr(request.user, "_perm_cache"):
                del request.user._perm_cache

            if not request.user.has_perm(permission):
                return JsonResponse(
                    {"error": f"Permission denied: {permission}"},
                    status=403
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator



def admin_required(view_func):
    
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.META.get("HTTP_AUTHORIZATION", "").replace("Bearer ", "")
        payload = decode_token(token)
        if not payload:
            return JsonResponse({"error": "Invalid token"}, status=401)

        user = User.objects.filter(id=payload["user_id"]).first()
        if not user or not user.is_superuser:
            return JsonResponse({"error": "Admin access required"}, status=403)

        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper


@csrf_exempt
def register_user(request):
    if request.method != "POST":
        return json_error("POST request required", 405)
    data = json.loads(request.body)
    if not data.get("username") or not data.get("password"):
        return json_error("Username and password required", 400)
    if User.objects.filter(username=data["username"]).exists():
        return json_error("Username already exists", 400)

    user = User.objects.create_user(username=data["username"], password=data["password"])

    default_perm = Permission.objects.filter(codename="can_create_note").first()
    if default_perm:
        user.user_permissions.add(default_perm)
        user._perm_cache = None  

    return JsonResponse({"message": "User registered with default permission"}, status=201)


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
    if not payload or payload.get("type") != "refresh":
        return json_error("Invalid refresh token", 401)
    user = User.objects.filter(id=payload["user_id"]).first()
    return JsonResponse({"access_token": create_token(user, "access")})



@csrf_exempt
def assign_permission(request):
    if request.method != "POST":
        return json_error("POST request required", 405)

    token = request.META.get("HTTP_AUTHORIZATION", "").replace("Bearer ", "")
    payload = decode_token(token)
    if not payload:
        return json_error("Invalid or missing token", 401)

    admin = User.objects.filter(id=payload.get("user_id")).first()
    if not admin or not admin.is_superuser:
        return json_error("Admin only", 403)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return json_error("Invalid JSON", 400)

    user = User.objects.filter(id=data.get("user_id")).first()
    perm = Permission.objects.filter(codename=data.get("permission")).first()
    if not user or not perm:
        return json_error("Invalid user or permission", 400)

    action = data.get("action")
    if action == "add":
        user.user_permissions.add(perm)
    elif action == "remove":
        user.user_permissions.remove(perm)
    else:
        return json_error("Action must be add or remove", 400)

    user._perm_cache = None
    return JsonResponse({"message": "Permission updated"})


@method_decorator(csrf_exempt, name="dispatch")
class CreateNoteView(View):

    @method_decorator(jwt_required)
    @method_decorator(perm_required("register.can_create_note"))
    def post(self, request):
        try:
            
            body = request.body
            if isinstance(body, bytes):
                body = body.decode("utf-8")

            data = json.loads(body)

            title = data.get("title")
            content = data.get("content")

            if not title or not content:
                return JsonResponse(
                    {"error": "Title and content are required"},
                    status=400
                )

            
            note = Note.objects.create(
                user=request.user,
                title=title,
                content=content
            )

            return JsonResponse(
                {
                    "message": "Note created successfully",
                    "note_id": note.id
                },
                status=201
            )

        except json.JSONDecodeError:
            return JsonResponse(
                {"error": "Invalid JSON format"},
                status=400
            )

        except Exception as e:
            return JsonResponse(
                {
                    "error": "Server error",
                    "details": str(e)
                },
                status=500
            )




@method_decorator(csrf_exempt, name="dispatch")
class UpdateNoteView(View):
    @method_decorator(jwt_required)
    @method_decorator(perm_required("register.can_update_note"))
    def put(self, request, note_id):
        note = Note.objects.filter(id=note_id, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)

        try:
            data = json.loads(request.body)
        except:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        note.title = data.get("title", note.title)
        note.content = data.get("content", note.content)
        note.save()
        return JsonResponse({"message": "Note updated", "note_id": note.id})


@method_decorator(csrf_exempt, name="dispatch")
class DeleteNoteView(View):
    @method_decorator(jwt_required)
    @method_decorator(perm_required("register.can_delete_note"))
    def delete(self, request, note_id):
        note = Note.objects.filter(id=note_id, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)

        note.delete()
        return JsonResponse({"message": "Note deleted"})


@method_decorator(csrf_exempt, name="dispatch")
class ListNotesView(View):
    @method_decorator(jwt_required)
    def get(self, request):
        notes = Note.objects.filter(user=request.user)
        data = [
            {
                "note_id": n.id,
                "title": n.title,
                "content": n.content,
                "category": n.category.name if n.category else None,
                "is_favorite": n.is_favorite,
            } for n in notes
        ]
        return JsonResponse(data, safe=False)


@method_decorator(csrf_exempt, name="dispatch")
class CreateCategoryView(View):
    @method_decorator(jwt_required)
    @method_decorator(perm_required("register.can_create_category"))
    def post(self, request):
        data = json.loads(request.body)
        name = data.get("name")
        if not name:
            return json_error("Category name is required", 400)
        if Category.objects.filter(user=request.user, name=name).exists():
            return json_error("Category already exists", 400)
        category = Category.objects.create(user=request.user, name=name)
        return JsonResponse({"category_id": category.id, "name": category.name, "message": "Category created"})


@method_decorator(csrf_exempt, name="dispatch")
class AssignCategoryView(View):
    @method_decorator(jwt_required)
    def put(self, request, note_id):
        note = Note.objects.filter(id=note_id, user=request.user).first()
        if not note:
            return json_error("Note not found", 404)
        data = json.loads(request.body)
        category = Category.objects.filter(id=data.get("category_id")).first()
        if not category:
            return json_error("Category not found", 404)
        note.category = category
        note.save()
        return JsonResponse({"message": "Category assigned"})



@method_decorator(csrf_exempt, name="dispatch")
class AdminViewAllUsersView(View):
    @method_decorator(admin_required)
    def get(self, request):
        users = User.objects.all().prefetch_related("notes")
        data = []
        for user in users:
            data.append({
                "user_id": user.id,
                "username": user.username,
                "notes": [{"note_id": note.id, "title": note.title} for note in user.notes.all()]
            })
        return JsonResponse(data, safe=False)


@method_decorator(csrf_exempt, name="dispatch")
class AdminDeleteUserView(View):
    @method_decorator(admin_required)
    def delete(self, request, user_id):
        if request.user.id == user_id:
            return json_error("Admin cannot delete themselves", 400)
        user = User.objects.filter(id=user_id).first()
        if not user:
            return json_error("User not found", 404)
        user.delete()
        return JsonResponse({"message": "User and related notes deleted"})


@method_decorator(csrf_exempt, name="dispatch")
class AdminDeleteNoteView(View):
    @method_decorator(admin_required)
    def delete(self, request, note_id):
        note = Note.objects.filter(id=note_id).first()
        if not note:
            return json_error("Note not found", 404)
        note.delete()
        return JsonResponse({"message": "Note deleted by admin"})


@method_decorator(csrf_exempt, name="dispatch")
class ViewNoteView(View):

    @method_decorator(jwt_required)
    def get(self, request, note_id):
        note = Note.objects.filter(id=note_id, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)

        return JsonResponse({
            "note_id": note.id,
            "title": note.title,
            "content": note.content,
            "category": note.category.name if note.category else None,
            "is_favorite": note.is_favorite,
            
        })

@method_decorator(csrf_exempt, name="dispatch")
class SearchNotesView(View):

    @method_decorator(jwt_required)
    def get(self, request):
        query = request.GET.get("q", "").strip()
        if not query:
            return JsonResponse([], safe=False)

        notes = Note.objects.filter(
            user=request.user
        ).filter(
            Q(title__icontains=query) |
            Q(content__icontains=query) |
            Q(category__name__icontains=query)
        ).select_related("category")

        data = [
            {
                "note_id": n.id,
                "title": n.title,
                "content": n.content,
                "category": n.category.name if n.category else None,
                "is_favorite": n.is_favorite,
            }
            for n in notes
        ]

        return JsonResponse(data, safe=False)


@method_decorator(csrf_exempt, name="dispatch")
class ToggleFavoriteView(View):

    @method_decorator(jwt_required)
    def put(self, request, note_id):
        note = Note.objects.filter(id=note_id, user=request.user).first()
        if not note:
            return JsonResponse({"error": "Note not found"}, status=404)

        note.is_favorite = not note.is_favorite
        note.save()

        return JsonResponse({
            "message": "Favorite updated",
            "note_id": note.id,
            "is_favorite": note.is_favorite
        })
