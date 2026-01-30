Landon Middle News — local dev README

Quick start (no admin required)

1. Recommended: install Python for current user from https://www.python.org/downloads/ (select "Install for current user" and check "Add Python to PATH"). If you cannot install, the project includes an embeddable Python bootstrap process (see below).

2. From the project folder in PowerShell:

```powershell
# Option A — normal install
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py

# Option B — embeddable (if you cannot install Python)
# The project can run with an embeddable Python binary placed in .python-embed.
# On this project I used a small script to download the embeddable zip, bootstrap pip, and run the app.
```

3. Open http://127.0.0.1:5000 in your browser.

Accounts and roles
- Default admin: username `Matcha`, password `gwcba6Bj`.
- Admin can assign roles (user, editor, admin) at `/admin`.

Admin features
- `/admin`: manage users; quick links to manage pages, articles, and editor console.
- `Manage Pages` allows editing announcements, clubs, sports, voices and the home page via a WYSIWYG editor.
- `Clear All Site Content` deletes all articles and submissions and clears pages (admin-only).
- `Seed Example Content` (admin-only) populates helpful example articles and page content suitable for a middle-school site.

Editor features
- `/editor`: create drafts, submit for review, and (if admin) publish directly.
- `/articles`: list articles; `/article/<id>` view an article.

Notes
- This is a small dev server and should not be used in production as-is.
- The project uses an embeddable Python technique to run without admin rights; prefer installing Python normally for ongoing development.

GitHub CI / Container Registry
- A GitHub Actions workflow is included to build and push a Docker image to the GitHub Container Registry (GHCR) on push to `main`.

How to use the image
- After pushing to `main`, the image will be available as `ghcr.io/<your-org-or-username>/landon-news:latest` and `ghcr.io/<your-org-or-username>/landon-news:<sha>`.
- Configure a hosting provider (Render, Fly, DigitalOcean App Platform, etc.) to pull the image from GHCR. Many providers accept a registry URL and a username/token.

Repository secrets
- The workflow uses the repository `GITHUB_TOKEN` to authenticate with GHCR automatically; no extra secret is required to push from this repository.
- If you prefer Docker Hub, set `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` as repository secrets and add a small step to the workflow to log in and push to Docker Hub.

Example: deploy to Render (manual steps)
1. Create a new Web Service on Render and choose to deploy from a Docker image.
2. For the image, provide `ghcr.io/<your-org-or-username>/landon-news:latest`.
3. If Render cannot access GHCR by default, create a Render Private Registry using a GitHub Personal Access Token (with `read:packages`).
 
Deployment to Heroku via GitHub
--------------------------------

This repository includes a GitHub Actions workflow that can deploy the app to Heroku when you push to `main`.

Steps to deploy from your machine (PowerShell):

```powershell
# initialize a local git repo (if needed)
git init
git add .
git commit -m "Initial commit"
git branch -M main
# create the remote repository on GitHub and replace the URL below
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

Repository secrets required (add in GitHub > Settings > Secrets):

- `HEROKU_API_KEY` — your Heroku API key (found in Heroku account settings)
- `HEROKU_APP_NAME` — the target Heroku app name (create the app first on Heroku)
- `HEROKU_EMAIL` — the Heroku account email

Once those secrets are set, any push to `main` will run the workflow and deploy the current app to the specified Heroku app.

If you instead want automated builds to a container registry or another host, let me know and I can add a workflow for GHCR, Docker Hub, or Render.

