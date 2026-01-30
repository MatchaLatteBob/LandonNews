import os
import requests

BASE = os.environ.get('BASE_URL', 'http://127.0.0.1:5000')
API_KEY = os.environ.get('API_KEY')

def headers():
    h = {'Content-Type':'application/json'}
    if API_KEY:
        h['X-API-Key'] = API_KEY
    return h

def update_announcements():
    url = f"{BASE}/api/pages/announcements"
    data = {"title": "Latest Announcements", "content": "<p>School assembly Friday at 9am.</p>"}
    r = requests.post(url, json=data, headers=headers())
    print('update_announcements', r.status_code, r.text)

def create_article():
    url = f"{BASE}/api/articles"
    data = {"title":"New Club Signup","content":"<p>Sign up for clubs next week.</p>","author":"Admin","status":"published"}
    r = requests.post(url, json=data, headers=headers())
    print('create_article', r.status_code, r.text)

if __name__ == '__main__':
    update_announcements()
    create_article()
