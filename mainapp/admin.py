from django.contrib import admin

# Register your models here.
from .models import Users, Organizations

@admin.register(Users)
class UsersAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'fullname', 'contact' , 'created_at')
    search_fields = ('username', 'email', 'fullname')
    list_filter = ('created_at',)

@admin.register(Organizations)
class OrganizationsAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name', 'created_at')