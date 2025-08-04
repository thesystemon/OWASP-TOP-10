## 🔐 **Broken Access Control Checklist (Offensive Security Focused)**

> Use this checklist during reconnaissance, enumeration, exploitation, and reporting. This focuses on bypassing or manipulating access controls intentionally implemented by developers.

---

### 🧭 **1. Reconnaissance & Discovery**

* [ ] ✅ **Identify user roles and permissions** (Admin, Moderator, Basic User, Guest, etc.)
* [ ] ✅ **Crawl all endpoints** using tools like Burp Suite, OWASP ZAP, FFUF, Dirsearch.
* [ ] ✅ **Observe URL structures** that may suggest ID-based access:
  `/user/profile?id=123`, `/admin/delete?id=456`, etc.
* [ ] ✅ **Note common patterns** like `user_id`, `account_id`, `role`, `priv`, `is_admin`.

---

### 🎯 **2. Insecure Direct Object References (IDOR)**

* [ ] ✅ Test direct access to objects by changing `ID`, `username`, `account` in URLs:

  * `/invoice/123` → `/invoice/124`
  * `/user/kunal` → `/user/admin`
* [ ] ✅ Try modifying POST body parameters or JSON payloads.
* [ ] ✅ Test file access via path manipulation:
  `/files/document.pdf` → `/files/confidential.pdf`

---

### 🔄 **3. Forced Browsing (Unprotected URLs)**

* [ ] ✅ Try accessing endpoints that shouldn't be available to your role.

  * Example: `/admin/dashboard`, `/internal/settings`
* [ ] ✅ Remove UI controls (buttons/links) via dev tools and manually browse hidden functions.

---

### ⚖️ **4. Privilege Escalation / Role Manipulation**

* [ ] ✅ Test if you can escalate roles via:

  * Changing values like `"role": "user"` → `"role": "admin"`
  * Modifying cookies, JWT, or local storage items
* [ ] ✅ Observe response changes or unauthorized access

---

### 🔄 **5. Method Tampering & HTTP Verb Confusion**

* [ ] ✅ Test multiple HTTP methods: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`
* [ ] ✅ Check if `DELETE /user/kunal` is blocked for user but allowed via `POST` or `PUT`
* [ ] ✅ Bypass CORS preflight using alternate verbs

---

### 🔐 **6. Bypassing Access Control Mechanisms**

* [ ] ✅ Try bypassing using:

  * Null byte injection (`%00`)
  * Encoded characters (`..%2f..`)
  * Alternate paths (`/..;/admin`)
* [ ] ✅ Remove `Authorization` header and test fallback
* [ ] ✅ Swap tokens between users

---

### 🔄 **7. Parameter Pollution / Mass Assignment**

* [ ] ✅ Test with duplicate parameters:

  * `?role=user&role=admin`
* [ ] ✅ Try adding hidden fields like `isAdmin=true` to request bodies
* [ ] ✅ Fuzz for additional parameters using a wordlist (e.g., SecLists, param-miner)

---

### 🧾 **8. JWT & Token-Based Failures**

* [ ] ✅ Modify JWT `alg` to `none` if not validated
* [ ] ✅ Bruteforce weak JWT secrets (use `jwt_tool`)
* [ ] ✅ Replay expired or revoked tokens
* [ ] ✅ Swap tokens between users (token confusion)

---

### ⛔ **9. Unvalidated Access on APIs**

* [ ] ✅ Use Postman/Burp to access internal APIs directly:

  * `/api/v1/users/delete?id=5`
* [ ] ✅ Test for unauthenticated access to admin APIs
* [ ] ✅ Try user context switching without re-authentication

---

### 💥 **10. Session Management Issues**

* [ ] ✅ Reuse cookies/session IDs across users
* [ ] ✅ Check if logout doesn't invalidate tokens
* [ ] ✅ Check for predictable or sequential session tokens

---

### 📤 **11. File Access & Functionality Abuse**

* [ ] ✅ Upload files to test override: `/uploads/image.png` → `/uploads/.htaccess`
* [ ] ✅ Download or delete files that shouldn't be accessible
* [ ] ✅ Abuse import/export features to leak data

---

### 🔁 **12. Rate Limiting Bypass**

* [ ] ✅ Bruteforce IDOR or role endpoints without triggering lockout
* [ ] ✅ Try multiple roles using automation tools like:

  * Burp Intruder
  * Turbo Intruder
  * ffuf or wfuzz

---

## 📌 Additional Tips

* 🧪 Always verify **authorization checks** are enforced **server-side**.
* 🔄 Reuse and replay traffic using **Burp Suite repeater** to test behavior.
* 🛑 Use **multiple user contexts** during testing (guest, normal, admin).
* 🧑‍💻 Use automation for role/ID fuzzing: ffuf, qsreplace, Param Miner, etc.

---

## 📋 Reporting Template Snippet (for BAC)

```markdown
**Vulnerability:** Insecure Direct Object Reference (IDOR)  
**Endpoint:** `GET /api/v1/invoice?id=112`  
**Impact:** Unauthorized access to another user’s invoice  
**Reproduction Steps:**
1. Login as user A
2. Intercept request to `/invoice?id=112`
3. Modify `id=112` → `id=113`
4. Observe that invoice of another user is accessible

**Severity:** High  
**Fix Recommendation:** Enforce server-side authorization using session or token-based access verification.
```

---

