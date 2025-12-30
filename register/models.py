import uuid
from django.db import models
from django.conf import settings


class Category(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="categories"
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Categories"
        unique_together = ("user", "name")
        permissions = [
            ("can_create_category", "Can create category"),
        ]

    def __str__(self):
        return self.name


class Note(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notes"
    )
    title = models.CharField(max_length=255)
    content = models.TextField()
    category = models.ForeignKey(
        Category,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="notes"
    )
    is_favorite = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        permissions = [
            ("can_create_note", "Can create note"),
            ("can_update_note", "Can update note"),
            ("can_delete_note", "Can delete note"),
            ("can_create_category", "Can create category"),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return self.title
