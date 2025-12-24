import uuid
from django.db import models
from django.contrib.auth.models import User


class Category(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="categories"
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Categories"
        unique_together = ("user", "name")  

    def __str__(self):
        return self.name


class Note(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="notes"
    )
    title = models.CharField(max_length=200)
    content = models.TextField()

    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="notes"
    )

    is_favorite = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title

class AuthToken(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="custom_token" 
    )
    token = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username

