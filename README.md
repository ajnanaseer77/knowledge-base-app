# Feedback & Review System (Django)

A simple Django-based feedback and review system with:
- User registration & login
- Token-based authentication
- Submit, update, delete reviews
- Filter & average rating
- Admin reply (is_staff only)
- PostgreSQL database

## Tech Stack
- Python
- Django
- PostgreSQL
- Postman (API testing)

## How to Run
```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver