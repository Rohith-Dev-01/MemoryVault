# 🔐 Memory Vault – Digital Legacy Management System

<p align=*center*> <strong>Your memories deserve to live on.</strong> </p>

<p align=*center*> A full-stack digital legacy management platform to catalog digital assets, preserve personal memories, manage final wishes, and govern legacy access through multi-stage inactivity monitoring and administrative verification. </p>

<p align=*center*> <a href=*[https://memory-vault-main.vercel.app/*>🚀](https://memory-vault-main.vercel.app/">🚀) Live Demo</a> </p>

---

## 📌 About the Project

In today's digital world, individuals maintain numerous online accounts, including social media profiles, email services, cloud drives, digital subscriptions, and personal archives. However, most people lack a structured, secure plan for managing these digital assets in the event of prolonged inactivity or absence.

**Memory Vault** is a full-stack Digital Legacy Management System designed to help users document their digital footprint, assign asset-specific final wishes, nominate trusted contacts, and preserve meaningful farewell letters.

Unlike simplistic auto-release tools, Memory Vault enforces a strict **zero-password storage policy** and a **human-verified release governance model**—ensuring that prolonged inactivity triggers progressive check-in reminders rather than automatic data exposure, and private records are released only after explicit administrative review.

---

## ✨ Key Features

- **Role-Based Authentication & Separate Dashboards:** Distinct login flows and isolated dashboards for **Vault Users** (`dashboard.html`) and **Administrators** (`admin.html`), preventing cross-role access.
- **Digital Asset Management (Zero-Password Policy):** Add, edit, and organize online accounts, cloud storage, and subscriptions using account identifiers and notes—never collecting or storing third-party passwords.
- **Per-Asset Final Wishes:** Assign tailored instructions to each digital asset (*Preserve account*, *Preserve selected memories*, *Share selected information*, *Request memorialization*, or *Request official deletion/cancellation*) alongside a designated trusted steward.
- **Trusted Contacts & Token Invitations:** Nominate trusted individuals with unique invitation tokens and track invitation states (`Pending`, `Accepted`, `Declined`). Accepting an invitation never automatically grants access to private vault data.
- **Memories & Farewell Letters:** Create, edit, and organize personal memories and farewell letters addressed to designated recipients.
- **4-Stage Inactivity Monitoring & Demo Simulator:** Automated escalation workflow across **Day 30** (First Reminder), **Day 35** (Second Reminder), **Day 40** (Final Reminder), and **Day 45** (Trusted Contact Check-In Alert), paired with a live one-click simulation panel and manual check-in reset.
- **Trusted Contact Legacy Access Portal:** Public portal (`legacy-access.html`) allowing trusted contacts to submit verification requests and view strictly scoped items once approved.
- **Administrator Verification Dashboard:** Dedicated admin interface (`admin.html`) to review, approve, or reject legacy access requests with audit-logged remarks.
- **Printable Legacy Summary:** Consolidated dossier (`summary.html`) of digital assets, final wishes, trusted contacts, and inactivity settings formatted with `@media print` rules for clean **PDF** export.

---

## ⚙️ How It Works

1. **Register & Sign In:** Create a Vault User account (or sign in using role selection for Vault User or Administrator).
2. **Catalog Digital Assets:** Record online platforms, categories, and account identifiers without storing sensitive passwords.
3. **Assign Final Wishes:** Define specific directives and stewards for each registered asset.
4. **Nominate Trusted Contacts:** Add trusted contacts and manage invitation tokens and acceptance status.
5. **Preserve Memories & Letters:** Write personal keepsake messages and farewell letters for loved ones.
6. **Monitor Inactivity Cycles:** Test the 30-, 35-, 40-, and 45-day escalation stages via the interactive simulation controls or reset the cycle via manual check-in.
7. **Review & Release via Admin Verification:** Trusted contacts submit legacy access requests through the public portal, and administrators review and approve scoped data releases.

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| **HTML5** | Semantic page structure across user, public, and admin portals |
| **CSS3** | Custom editorial design system, responsive layouts, and `@media print` PDF styling |
| **Vanilla JavaScript (ES6+)** | Client-side validation, Fetch API communication, and role-based route guards |
| **Node.js / Express & PHP 8+** | Serverless API backend on Vercel (`server.ts`) with full XAMPP PHP REST API compatibility |
| **PostgreSQL (Supabase)** | Cloud relational database storing users, assets, wishes, contacts, memories, requests, and audit logs |
| **Vercel** | Cloud hosting and serverless deployment |

---

## 💾 Database Architecture (Supabase / PostgreSQL)

Memory Vault persists all application data in a relational **PostgreSQL** database hosted on **Supabase**, accessed via parameterized **SQL** queries (`DATABASE_URL` over **SSL**).

**Core Relational Tables:**
- `users` & `admin_users` — Separate credential tables using `bcrypt` password hashing
- `digital_assets` — User-owned online account metadata (identifiers only)
- `final_wishes` — Asset-linked legacy directives and assigned stewards
- `trusted_contacts` — Nominated contacts with unique invitation tokens and statuses
- `memories` — Personal memories and recipient-linked farewell letters
- `legacy_plans` — User inactivity tracking timestamps and escalation state
- `legacy_requests` — Trusted contact access requests and approval statuses
- `notification_logs` & `admin_action_logs` — Deduplicated reminder logs and administrative audit trails

---

## 🎨 UI Design System

Memory Vault features a calm, minimalistic, editorial aesthetic designed for clarity, accessibility, and trust.

**Color Palette:**
- **Warm Ivory:** `#**F5F1E8**` (Primary background)
- **Forest Green:** `#**29483B**` (Primary brand & actions)
- **Muted Terracotta:** `#**C77C61**` (Highlights & secondary accents)
- **Soft Sand:** `#**E8E3D8**` (Secondary containers)
- **Surface White & Borders:** `#**FFFFFF**` & `#**DDD8CA**`

**Typography:**
- **Headings:** *Playfair Display* (Editorial serif)
- **Body & UI Controls:** *DM Sans* (Clean geometric sans-serif)

---

## 🚀 Live Demo

Try the live deployed application here:

**[Memory Vault – Live Application](https://memory-vault-main.vercel.app/)**

### Demo Credentials

- **Vault User:** `[demo@memoryvault.com](mailto:demo@memoryvault.com)` / `Demo@**1234**`
- **Administrator:** `[admin@memoryvault.com](mailto:admin@memoryvault.com)` / `Admin@**1234**`

---

## 📂 Project Structure

```text
Project/
├── server.ts                 # Node.js/Express backend for Vercel serverless deployment
├── vercel.json               # Vercel build and routing configuration
├── package.json              # Node dependencies and scripts
└── **MEMORY**-**VAULT**/
    ├── frontend/
    │   ├── index.html            # Editorial landing page
    │   ├── register.html         # Vault user registration
    │   ├── login.html            # Role-aware login (Vault User / Administrator)
    │   ├── dashboard.html        # User dashboard, check-in reset & inactivity simulator
    │   ├── assets.html           # Digital asset **CRUD** manager
    │   ├── wishes.html           # Per-asset final wishes manager
    │   ├── contacts.html         # Trusted contacts & token invitation manager
    │   ├── memories.html         # Memories & farewell letters gallery
    │   ├── summary.html          # Printable / Save-as-**PDF** legacy dossier
    │   ├── legacy-access.html    # Public portal for trusted contact access requests
    │   ├── admin.html            # Dedicated administrator verification dashboard
    │   ├── css/
    │   │   └── style.css         # Editorial stylesheet, responsive & print rules
    │   └── js/
    │       ├── config.js         # **API** base **URL** configuration
    │       ├── api.js            # Fetch wrapper with credentials & **CSRF** headers
    │       └── script.js         # UI logic, validation & role-based route guards
    └── backend/
    ├── config/
    │   └── db.php            # Supabase PostgreSQL **PDO** connection (for **XAMPP**)
    ├── includes/
    │   ├── cors.php          # **CORS** & cross-origin cookie configuration
    │   ├── auth_middleware.php # Session & role verification helpers
    │   └── mailer.php        # Notification logging & email dispatch helper
    ├── api/                  # Modular **PHP** **REST** endpoints
    ├── cron/
    │   └── check_inactivity.php # Automated multi-stage inactivity escalation script
    └── database/
    └── supabase_schema.sql  # Complete PostgreSQL schema & demo seed data
```

## 💻 Run Locally


Option 1: Node.js + Supabase (Cloud Setup)
Clone the repository:

Bash git clone [https://github.com/kangokarrohith-gif/MemoryVault.git](https://github.com/kangokarrohith-gif/MemoryVault.git) cd MemoryVault/Project Install dependencies:

Bash npm install Configure environment variables: Create a .env file inside Project/ and add your Supabase PostgreSQL Session Pooler **URI**:

Code snippet DATABASE_URL=postgresql://postgres.<PROJECT_REF>:<YOUR_PASSWORD>@[aws-0-ap-south-1.pooler.supabase.com:**5432**/postgres](https://aws-0-ap-south-1.pooler.supabase.com:**5432**/postgres) Start the local server:

Bash npm run dev Option 2: Local **PHP** / **XAMPP** + Supabase Copy Project/**MEMORY**-**VAULT** into C:\xampp\htdocs\**MEMORY**-**VAULT**.

Run backend/database/supabase_schema.sql in your Supabase **SQL** Editor.

Enable extension=pdo_pgsql and extension=pgsql in C:\xampp\php\php.ini and restart Apache.

Add your Supabase Session Pooler credentials to backend/config/db.php and open [http://localhost/**MEMORY**-**VAULT**/frontend/index.html.](http://localhost/**MEMORY**-**VAULT**/frontend/index.html.)


## 🔒 Privacy & Security Architecture Zero-Password Storage: The system strictly prohibits collecting or storing third-party account passwords.


Human-Verified Governance: Prolonged inactivity triggers check-in notifications only—inactivity alone is never treated as proof of death, and private records remain locked until an administrator explicitly approves a verified request.

Scoped Data Release: Approving a trusted contact's request reveals only the specific wishes and memories explicitly assigned to that contact.

Backend Hardening: Uses bcrypt password hashing, parameterized **SQL** queries against **SQL** injection, HttpOnly session cookies, **CSRF** tokens on state-changing requests, strict **WHERE** user_id = ? ownership checks, and **HTML** output escaping.


## 🔮 Future Enhancements Automated transactional email delivery via PHPMailer or Resend.


Multi-factor authentication (**MFA**) and government ID document upload for legacy request verification.

End-to-end client-side encryption for sensitive farewell letters and attachments.

Scheduled cron-job automation for background inactivity checks.

Direct integration guides for official platform legacy programs (Google Inactive Account Manager, Apple Digital Legacy, Meta Memorialization).


## 🎯 Project Objective


The primary objective of Memory Vault is to bridge the gap between personal digital organization and responsible legacy governance—giving individuals an intuitive, secure way to document their digital assets, preserve meaningful memories, and ensure their final wishes are carried out with human verification.


## 👨‍💻 Project Information Project Name: Memory Vault – Digital Legacy Management System


Project Type: Web Technology Mini Project

Domain: Full-Stack Web Development

Frontend: **HTML5**, **CSS3**, Vanilla JavaScript

Backend: Node.js (Express) & **PHP** 8+ (**REST** **API**)

Database: PostgreSQL (Supabase)

Deployment: Vercel
