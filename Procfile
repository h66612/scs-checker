web: sh -c "python -c 'from web_app import init_db; init_db()' && gunicorn web_app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 300"
