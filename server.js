# Warehouse Parts Tracker

## Deploy to Railway (recommended — free, public URL, works on any phone)

### Step 1 — Create a free Railway account
Go to **railway.app** and sign up with GitHub (easiest) or email.

### Step 2 — Deploy

**Option A — GitHub (best for updates):**
1. Push this folder to a GitHub repository
2. In Railway dashboard → New Project → Deploy from GitHub repo
3. Select your repo — Railway auto-detects Node.js and deploys

**Option B — Railway CLI (no GitHub needed):**
1. Install Railway CLI by opening Terminal/Command Prompt and running:
   ```
   npm install -g @railway/cli
   ```
2. In this folder, run:
   ```
   railway login
   railway init
   railway up
   ```

### Step 3 — Get your public URL
Railway dashboard → your project → Settings → Networking → Generate Domain.
You get a URL like: `https://warehouse-tracker-production.up.railway.app`

Open that URL on any phone, any network, anywhere.

### Step 4 — Set environment variables (important)
In Railway dashboard → your project → Variables, add:

| Variable      | Value                    | Why                                      |
|---------------|--------------------------|------------------------------------------|
| JWT_SECRET    | any long random string   | Keeps logins secure across restarts      |

### Step 5 — Persistent data (prevent data loss on redeploy)
By default Railway resets the filesystem on each deploy. To keep your data permanently:
1. Railway dashboard → your project → + New → Volume
2. Mount path: /data
3. Add environment variable: DB_PATH=/data/db.json

Your database will now survive all redeploys and restarts.

---

## Run locally (same WiFi only)

Node.js required: nodejs.org → install LTS version.

- Windows: double-click start-server.bat
- Mac: double-click start-server.command
- Any OS: run `node server.js` in this folder

Open http://localhost:3000 in your browser.
On phones (same WiFi): open http://YOUR-COMPUTER-IP:3000 in Safari.

---

## First login

Username: admin
Password: admin123

Change this password immediately in the Admin panel.

---

## User Roles

| Role          | Permissions                                                        |
|---------------|--------------------------------------------------------------------|
| Admin         | Everything + create/edit/delete users                              |
| Stager        | Add parts to jobs, stage parts, sign out parts, manage catalog     |
| Sign-out only | Can ONLY sign out parts already assigned to a job                  |

Key rule: No one can sign out a part unless it has been assigned to a job first.
The server rejects it — not just a UI restriction.

---

## Job Parts List

Before staging, Admins/Stagers build a parts list for each job:
- Open a job > Add Parts tab
- Scan each expected part, set quantity and notes
- Or import a CSV: barcode, name, qty, notes

Stagers see a live checklist: not staged / staged / picked up / overage.

---

## Backing up data

Local: copy db.json regularly.
Railway with Volume: data persists automatically.
To export everything: Reports tab > Export full report CSV.
