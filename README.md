# LandonNews
Landon Middle School News Website
## Quick Deploy to Fly.io (24/7 Free)

This repository includes a GitHub Actions workflow that automatically deploys to Fly.io on every push to `main`.

### Setup (one-time):

1. **Create a Fly.io account:** https://fly.io (free tier includes always-on 24/7 hosting)

2. **Create a Fly app from your machine** (or skip—the workflow will auto-create):
   ```bash
   flyctl auth login
   flyctl launch
   # Follow prompts, choose app name (e.g., "landon-news-app")
   ```

3. **Generate a Fly API token:**
   ```bash
   flyctl auth token
   # Copy the output
   ```

4. **Add GitHub Secrets** (in your repo: Settings → Secrets and variables → Actions):
   - `FLY_API_TOKEN` = paste the token from step 3

5. **Push to `main`:**
   ```bash
   git add .
   git commit -m "Ready to deploy"
   git push origin main
   ```

The workflow will automatically deploy! Check GitHub Actions tab for status and your app URL (usually `https://<app-name>.fly.dev`).

### Manual deploy (if needed):
```bash
flyctl deploy
```

### Logs:
```bash
flyctl logs
```