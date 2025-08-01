
---

# 🛑 Broken Access Control – Penetration Testing Notes

---

## 📌 What is Broken Access Control?

**Access control** determines what authenticated users are allowed to do.
When this control is **improperly implemented**, attackers can:

* Act as other users (horizontal privilege escalation)
* Act as admins (vertical privilege escalation)
* Access unauthorized functions or data

This failure is called **Broken Access Control**.

---

## 🧠 Key Concepts

| Term                                        | Meaning                                                             |
| ------------------------------------------- | ------------------------------------------------------------------- |
| **Access Control**                          | Mechanism to restrict actions based on user's role                  |
| **Broken Access Control**                   | When restrictions fail or can be bypassed                           |
| **Horizontal Escalation**                   | Accessing another user's data or actions                            |
| **Vertical Escalation**                     | Gaining admin/moderator privileges                                  |
| **Forced Browsing**                         | Accessing endpoints not meant for the user (e.g., /admin)           |
| **Insecure Direct Object Reference (IDOR)** | Accessing internal objects by manipulating input (e.g., user\_id=2) |

---

## 🔎 Real-World Example – Insecure Direct Object Reference (IDOR)

### Scenario:

A bank website uses the following URL to fetch account statements:

```
GET https://bank.com/accounts/view?acc_id=12345
```

An attacker **modifies the parameter**:

```
GET https://bank.com/accounts/view?acc_id=12346
```

If no proper check is in place, the attacker can now view **someone else's account details.**

### What’s broken?

The system failed to verify whether the current user owns `acc_id=12346`.

---

## 🧪 Common Access Control Vulnerabilities

| Type                                      | Description                                                                |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| **IDOR**                                  | Accessing unauthorized data by changing identifiers                        |
| **Missing Function-Level Access Control** | Frontend hides buttons, but backend does not verify user roles             |
| **Privilege Escalation**                  | Changing your role or performing admin actions                             |
| **Method Tampering**                      | Changing HTTP method (e.g., GET to DELETE) to perform unauthorized actions |
| **Unprotected Admin Interfaces**          | Publicly accessible /admin or /dashboard routes                            |
| **CORS Misconfigurations**                | Allowing unauthorized domains to access APIs                               |

---

## 🔐 Real-World Breaches

### 1. **Facebook (2021)**

* **What Happened?** An IDOR flaw allowed access to user's private data by manipulating GraphQL query IDs.
* **Impact:** Potential data exposure of user profiles and private messages.
* **Fix:** Facebook tightened role and object ownership checks in the GraphQL layer.

---

### 2. **Uber (2016)**

* **What Happened?** A user could escalate privileges and view sensitive information using IDOR.
* **Impact:** Hacker accessed sensitive internal data.
* **Fix:** Authorization checks added to API endpoints.

---

### 3. **Instagram (2020)**

* **What Happened?** Researchers accessed private archived stories via GraphQL endpoints.
* **Impact:** Privacy violation and potential unauthorized content viewing.
* **Fix:** Backend access checks updated.

---

## 🛠️ How to Test for Broken Access Control (as a Pentester)

### ✅ Manual Testing Steps:

1. **Check for Hidden Functions**

   * Look at JavaScript or HTML to find hidden endpoints or buttons
2. **Tamper Parameters**

   * Try changing `user_id`, `doc_id`, etc.
   * Use Burp Suite to intercept and modify requests
3. **Change HTTP Methods**

   * Try PUT, DELETE, POST where GET is expected
4. **Test Direct URLs**

   * Try to access `/admin`, `/internal`, `/settings` directly
5. **Replay Session Cookies**

   * Use another user’s token/cookie and see what data is visible
6. **Role Manipulation**

   * Change roles in a request payload, like `"role": "admin"` and see if it works

---

## 🔐 Tools for Testing

* 🔍 **Burp Suite** – Intercept and tamper HTTP requests
* 🔧 **OWASP ZAP** – Automated scanning for access control issues
* 🧪 **Postman** – Testing APIs with different roles and tokens
* 🛡️ **JWT.io** – Modify and test JWT tokens

---

## 🧰 Example: Testing with Burp Suite

1. Login as a normal user.
2. Intercept request to:

   ```
   GET /orders/view?order_id=1001
   ```
3. Modify `order_id` to `1002`.
4. Forward the request.
5. If data is shown → **Broken Access Control confirmed**

---

## ✅ Best Practices for Developers (To Prevent)

* **Enforce Access Control on Server-Side Only**
  → Never trust client-side controls (like hidden buttons)

* **Use Role-Based Access Controls (RBAC)**
  → Only allow users to access what they are authorized for

* **Use Object Ownership Checks**
  → Always verify if the object being accessed belongs to the user

* **Avoid Security by Obscurity**
  → Don’t assume "hidden" endpoints are safe

* **Use Secure ID Systems (UUIDs)**
  → Prevent easy ID enumeration (e.g., don’t use 1,2,3...)

---

## 📌 Summary

| Concept         | Key Point                                               |
| --------------- | ------------------------------------------------------- |
| Definition      | Failure in restricting what users can access            |
| Common Attacks  | IDOR, privilege escalation, method tampering            |
| Real Breaches   | Facebook, Uber, Instagram                               |
| Tools           | Burp, ZAP, Postman                                      |
| Prevention Tips | Server-side checks, role verification, ownership checks |

---

Great! You're aiming to **discover real-world Broken Access Control (BAC)** during **bug bounty or penetration testing**—so let's focus on **advanced yet practical examples** that mirror how these flaws appear in the wild. I’ll give:

* 🔍 Advanced BAC Examples
* 🧪 How to Detect/Test Them
* 🎯 What Makes Them Vulnerable
* 🛡️ What a Secure App Should Do

---

## 🚨 Advanced Broken Access Control Examples

---

### 1. **IDOR via API – Accessing Other User’s Files**

#### 📍 Example:

```http
GET /api/files/download?file_id=9283
Authorization: Bearer eyJhbGciOi...
```

🔁 Change `file_id=9283` to `file_id=9284`
If you can download someone else's file → **IDOR**

#### 🧪 Testing Tip:

* Use **Burp Repeater** to fuzz `file_id` with sequential values.
* Use **Python script** or **ffuf** to automate ID fuzzing.

#### ❌ Vulnerable:

No ownership check for the file ID.

#### ✅ Fix:

Backend must verify:

```python
if file.owner_id != current_user.id:
    return "Unauthorized", 403
```

---

### 2. **Admin Function Hidden in UI but Exposed via HTTP**

#### 📍 Example:

Normal user UI shows:

```html
<!-- Button not shown -->
```

But API:

```http
POST /api/user/ban
Payload: {"user_id": 101}
```

Send that as a regular user – **if it works, you’ve banned someone as a non-admin**.

#### 🧪 Testing Tip:

* Use **Burp Logger++** or **ZAP** to view all hidden or unused endpoints.
* Try accessing known admin actions directly.

#### ❌ Vulnerable:

No role validation in backend.

---

### 3. **Privilege Escalation via Role Modification in Profile Update**

#### 📍 Example:

```http
PUT /api/profile/update
{
  "username": "kunal",
  "role": "admin"
}
```

🧪 If you get elevated rights without being an admin → 🔥Critical BAC

#### 🧪 Testing Tip:

* Look at hidden form fields or unused JSON parameters.
* Fuzz JSON fields like `"role"`, `"is_admin"`, `"privilege"`.

#### ❌ Vulnerable:

Accepting client-submitted roles.

---

### 4. **Force Browsing Admin Panel Without Auth**

#### 📍 Example:

```http
GET /admin/settings
```

Even as an unauthenticated or normal user.

#### 🧪 Testing Tip:

* Use **dirsearch**, **ffuf**, or **Gobuster** with common admin wordlists.

```bash
ffuf -u https://target.com/FUZZ -w admin-panels.txt -fc 403,404
```

Common paths:

* `/admin`
* `/config`
* `/settings`
* `/internal`

---

### 5. **Modifying URL Parameters in Frontend-Only Controlled Systems**

#### 📍 Example:

You’re logged in to:

```http
GET /dashboard?user_id=104
```

🧪 Change `user_id=104` → `user_id=105`
If access is granted → BAC confirmed.

Sometimes, even session data is stored in **LocalStorage** and used insecurely in frontend.

---

### 6. **Method Tampering: Using PUT/DELETE as a Normal User**

#### 📍 Example:

```http
DELETE /api/users/otheruser
```

If the endpoint doesn't validate roles → you delete other users.

🧪 Try sending methods like:

* PUT `/api/users/1/roles`
* DELETE `/api/products/1`

Use **Burp Intruder** to rotate methods.

---

### 7. **JWT Token Manipulation for Role Escalation**

#### 📍 Example JWT Token:

```json
{
  "user": "kunal",
  "role": "user"
}
```

🧪 Try changing:

```json
"role": "admin"
```

Re-sign JWT if it's unsigned or uses `alg: none` or weak keys.

#### ❌ Vulnerable:

If server accepts tampered JWTs without verifying integrity.

Use:

* [JWT.io debugger](https://jwt.io)
* **jwt\_tool** (for fuzzing JWTs)

---

### 8. **Accessing Staging or Debug APIs**

Some apps expose:

```
/v1/dev/api
/staging/users
/debug/config
```

These may skip access control entirely.

🧪 Tools:

```bash
ffuf -u https://target.com/FUZZ -w common-dev-paths.txt
```

---

## 🔍 Summary: Parameters and Endpoints to Fuzz

| Parameter    | Fuzzing Payloads             |
| ------------ | ---------------------------- |
| `user_id`    | 1, 2, 3...                   |
| `role`       | `"admin"`, `"moderator"`     |
| `access`     | `"true"`, `"full"`           |
| `is_admin`   | `true`, `1`, `"1"`           |
| `id` in path | `/users/2`, `/files/3`, etc. |
| Methods      | GET, POST, PUT, DELETE       |

---

## 🛡️ Bonus – Payloads to Try in JSON

```json
{
  "user_id": 1,
  "role": "admin"
}
```

```json
{
  "username": "kunal",
  "privileges": "root"
}
```

```json
{
  "access_level": 5
}
```

---

Absolutely, here’s your **Deep Dive into Broken Access Control (BAC)** from a **Pentester’s and Real-World Attacker’s Perspective**, combining OWASP, bug bounty techniques, backend logic flaws, real-world scenarios, fuzzing tricks, bypass payloads, testing methodologies, and mitigation strategies.

---

# 🧠 **Deep Dive: Broken Access Control for Pentesters and Bug Bounty Hunters**

---

## 📖 1. What is Access Control?

Access control defines **what resources a user can access** and **what actions** they can perform.

There are 3 main types:

* **DAC (Discretionary Access Control)** – Object owners define access.
* **MAC (Mandatory Access Control)** – Based on classification levels (e.g., military).
* **RBAC (Role-Based Access Control)** – Based on roles like "user", "admin".

---

## ❌ 2. What is Broken Access Control?

Broken Access Control occurs when an attacker **bypasses authorization** and:

* Accesses **unauthorized data** (IDOR)
* Performs **unauthorized actions** (e.g., DELETE as a normal user)
* Gains **elevated privileges** (admin access)

It is **ranked #1** in the [OWASP Top 10 – 2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).

---

## 🎯 3. Categories of BAC Vulnerabilities

| Category                    | Description                                      | Exploit Method                 |
| --------------------------- | ------------------------------------------------ | ------------------------------ |
| **IDOR**                    | Insecure access to objects via user-supplied IDs | Change URL or JSON parameter   |
| **Privilege Escalation**    | Gaining higher-level access                      | Modify roles or IDs            |
| **Forced Browsing**         | Accessing restricted resources via direct URLs   | Try `/admin` as a regular user |
| **Method Tampering**        | Unauthorized HTTP method use                     | Use DELETE instead of GET      |
| **Client-side Enforcement** | JS hides buttons, but backend fails to validate  | Use API directly               |
| **CORS Misconfiguration**   | Cross-origin access with relaxed policies        | CORS exploit via XHR           |

---

## 🧪 4. Deep Testing Techniques (Manual + Automated)

### 🔧 a. **Parameter Tampering**

**URL Example:**

```
https://target.com/profile?user_id=102
```

Try values:

* Lower or higher sequential numbers
* UUIDs of other users
* Negative numbers, NULL, empty

**API Example:**

```json
{
  "user_id": 101,
  "role": "admin"
}
```

Try:

* `"role": "admin"`
* `"isAdmin": true`
* `"access_level": 5`

Tools: Burp Intruder, Postman, ffuf

---

### 🔁 b. **Session and Cookie Replay**

* Log in with two users
* Copy token or session cookie from User A
* Access User B's data using User A's session

> Works especially in apps that only check for token presence but not user-object relationships.

---

### 🔥 c. **JWT Forgery or Modification**

**JWT Token Example:**

```json
{
  "user": "kunal",
  "role": "user"
}
```

Try:

* Modify `"role": "admin"`
* Use JWT with `alg: none`
* Bruteforce weak JWT secrets using `jwt_tool`, `jwt-cracker`

---

### 📂 d. **Directory & Path Traversal Access**

```
GET /api/files/../../../etc/passwd
```

Or:

```
GET /admin
GET /config/dev-config
```

Tools: ffuf, dirsearch, gobuster

---

### 🔍 e. **Testing Hidden Admin Endpoints**

Test unauthenticated or regular user access to:

* `/admin`
* `/dashboard`
* `/user/delete`
* `/settings`

> Use **Burp Suite** or **ZAP** to find hidden paths or analyze JS.

---

## 💡 5. Realistic Exploitation Scenarios

### ✅ Scenario 1 – Banking App IDOR

* API: `/api/transactions?acc_id=291`
* You change `acc_id` to someone else's → Access transaction history.

🧪 Exploit: Use Burp Repeater with number fuzzer on `acc_id`.

---

### ✅ Scenario 2 – Role Elevation via Profile Update

```http
PUT /api/profile
{
  "name": "kunal",
  "role": "admin"
}
```

If accepted, you become an admin.

---

### ✅ Scenario 3 – Disable 2FA or View Another User’s 2FA Code

```http
POST /api/2fa/get_code
{
  "user_id": 201
}
```

Change `user_id` → You receive another user’s 2FA.

---

### ✅ Scenario 4 – Delete Any User

```http
DELETE /api/users/delete?id=132
```

Change ID → Delete arbitrary accounts.

---

## 🔍 6. Recon & Enumeration for BAC Testing

* **Use Developer Tools**: Find hidden buttons, endpoints, or `role` parameters
* **Check JS Files**: Use tools like `LinkFinder` or `JSParser`
* **Log All Requests**: With Burp Logger++ to find endpoints not used in the UI
* **Try Different Roles**: Compare responses for `user`, `moderator`, `admin`

---

## 🔒 7. How to Prevent (Dev-side)

* Enforce **backend authorization** checks on **every request**
* Never rely on **client-side role checking**
* Use **secure and random object IDs** (avoid sequential IDs)
* Implement **RBAC with clear roles and scopes**
* Deny access by default (`deny unless explicitly allowed`)
* Log and alert on **access attempts to unauthorized resources**

---

## ⚙️ 8. Best Tools for BAC Hunting

| Tool                         | Purpose                               |
| ---------------------------- | ------------------------------------- |
| 🔍 Burp Suite                | Manual request tampering              |
| 🧪 Postman                   | API testing                           |
| 🔁 JWT Tool                  | JWT manipulation                      |
| 📂 ffuf/gobuster             | Endpoint fuzzing                      |
| 🔍 Autorize (Burp Extension) | Auto-check BAC across roles           |
| 🔬 ZAP                       | Passive scans and endpoint discovery  |
| 🧱 Fiddler                   | For intercepting desktop/web requests |

---

## 🏁 9. Checklist for BAC Testing

* [ ] Can you change object IDs and access unauthorized data?
* [ ] Can a normal user perform admin actions?
* [ ] Are any admin panels publicly accessible?
* [ ] Can you modify role/privilege fields in any request?
* [ ] Are there unprotected APIs or debug endpoints?
* [ ] Is the app using predictable or sequential IDs?
* [ ] Can you replay another user’s JWT/token/session?

---

## 🧠 Mindset of a BAC Attacker

* “What if I change this ID?”
* “What happens if I remove the token?”
* “Can I delete this object even if I don’t own it?”
* “Are there endpoints not visible in the UI?”
* “Can I elevate my privilege silently?”

---

## 📚 10. References

* [OWASP Top 10: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [PortSwigger BAC Labs](https://portswigger.net/web-security/access-control)
* [HackerOne Reports on IDOR](https://hackerone.com/search?type=report&labels=idor)
* Tools:

  * [`jwt_tool`](https://github.com/ticarpi/jwt_tool)
  * [`ffuf`](https://github.com/ffuf/ffuf)
  * [`Autorize`](https://github.com/Quitten/Autorize)

---

Here is the **text version** of your **Broken Access Control Mind Map**, structured for readability, and with **advanced additions** to make it even more comprehensive:

---

## 🧠 **Broken Access Control – Advanced Mind Map**

---

### ✅ **1. Types**

* IDOR (Insecure Direct Object References)
* Privilege Escalation
* Forced Browsing
* Method Tampering (GET → POST, etc.)
* Client-Side Enforcement Bypass
* CORS Misconfiguration
* Banking App IDOR
* Static URL Access without Permission

---

### ✅ **2. Real-World Scenarios**

* Profile Update → Role Escalation
* Delete Other Users → No Validation
* View 2FA of Others
* Bypass Email Change Verification
* Upload Files to Admin Directory
* Switch User IDs in Mobile Apps

---

### ✅ **3. Testing Techniques**

* Parameter Tampering
* JWT Token Manipulation (None algorithm, key injection)
* Path Traversal for Sensitive Files
* Method Fuzzing (e.g., TRACE, OPTIONS)
* Session Replay / Fixation
* Hidden Admin Routes Access
* URL ID Change with Another User’s ID
* API Payload Tampering
* Role Field Injection in JSON Body
* Force Browsing to Unlisted Paths
* Client-side JS Function Manipulation
* Logout Bypass via Back Navigation

---

### ✅ **4. Exploitation Vectors**

* Force Browsing
* Unprotected Endpoints
* Weak Token Checks
* Server-side Validation Missing
* CSRF + Broken Access Combo
* RBAC (Role-Based Access Control) Misconfigured
* Predictable Object IDs
* Absence of Session Context in APIs

---

### ✅ **5. Prevention**

* Proper RBAC Implementation
* Random & Non-Sequential Object IDs
* Audit Logging with Alerting
* Deny by Default Policy
* Use Token Binding
* Validate All Role Changes on Server Side
* Enforce Contextual Access Checks (e.g., `user_id == session_user`)
* OAuth Scopes & Access Filtering
* Disable Client-Side Role Enforcement

---

### ✅ **6. Tools**

* **Burp Suite** (with extensions: Authz, Autorize)
* **Postman** (for API manipulation)
* **JWT\_Tool** (JWT fuzzing and tampering)
* **ffuf** (for discovering hidden endpoints)
* **ZAP** (for automated scans)
* **Autorize** (Burp plugin for role-based access testing)
* **Access Control Testing Tools** (custom scripts or automation)

---

### ✅ **7. Checklist**

* Tamper Object IDs?
* Access Admin as User?
* Modify Roles?
* Replay Sessions?
* Hidden APIs?
* Elevate from Read → Write Privileges?
* Are Audit Logs Enabled?
* Are APIs Checking Ownership?

---

Here’s an **advanced checklist for Broken Access Control** based on your mind map, organized in a professional format with detailed explanations. This can be used for manual security assessments, bug bounty testing, or secure coding reviews.

---

## 🔍 **Broken Access Control – Advanced Checklist**

### ✅ 1. **Object-Level Authorization**

* [ ] Test for **IDOR (Insecure Direct Object Reference)** vulnerabilities by changing object IDs in URLs, forms, or JSON payloads.
* [ ] Attempt to **Tamper Object IDs** with another user’s object and observe if access is granted.
* [ ] Try both **numeric** and **UUID-based** object identifiers.
* [ ] Check if the app prevents access to **deleted/inactive** object IDs.

---

### ✅ 2. **Function-Level Access Control**

* [ ] Can a **low-privileged user** access **admin functions** by changing URLs or parameters?
* [ ] Are there **hidden admin routes** accessible via wordlist fuzzing (`ffuf`, `dirsearch`)?
* [ ] Check if certain **roles (e.g., user vs. moderator)** are enforced on the backend.

---

### ✅ 3. **Role Manipulation and Privilege Escalation**

* [ ] Attempt to **modify your role** using interceptable payloads or client-side values.
* [ ] Are there endpoints where you can **set roles manually** (e.g., `role=admin`)?
* [ ] Test **Profile Update** features for privilege escalation (e.g., becoming admin by editing a role field).
* [ ] Can you **access admin panels** or dashboards without the correct role?

---

### ✅ 4. **JWT / Session Manipulation**

* [ ] Try **modifying JWT tokens** (e.g., `role: user` → `role: admin`) and test the access control.
* [ ] Test for **JWT signature algorithm confusion** (e.g., change `alg: HS256` to `none`).
* [ ] Attempt **Session Replay** — use an old session to verify if it still grants access.

---

### ✅ 5. **Access Control in APIs**

* [ ] Tamper with **API request methods (GET, POST, PUT, DELETE)** to escalate actions.
* [ ] Check for **API Payload Tampering**, especially in JSON or GraphQL queries.
* [ ] Attempt **Path Traversal** via APIs to access unauthorized paths.
* [ ] Look for **unprotected endpoints** that should require authentication/authorization.

---

### ✅ 6. **URL and Parameter Manipulation**

* [ ] Try changing **query parameters** or **URL paths** to escalate actions (e.g., `/user/settings` → `/admin/settings`).
* [ ] Test for **forced browsing** to bypass navigation limitations.
* [ ] Perform **method fuzzing** with tools like `Burp Suite` Intruder or ZAP.

---

### ✅ 7. **Real-World Scenarios Simulation**

* [ ] Try to **view another user's 2FA data** or personal settings.
* [ ] Attempt to **delete another user** (e.g., `DELETE /api/users/123`).
* [ ] Test **banking or financial applications** for transactional access control issues.

---

### ✅ 8. **Security Controls & Prevention**

* [ ] Is **RBAC (Role-Based Access Control)** enforced on the server?
* [ ] Does the app use **randomized object IDs** (e.g., UUIDs instead of sequential IDs)?
* [ ] Are **audit logs** generated and monitored for unauthorized access attempts?
* [ ] Is access denied **by default** if role/authorization is not explicitly given?
* [ ] Are **tokens validated on the backend** (and not just trusted from client)?

---

### ✅ 9. **Automation Tools**

* [ ] Use **Burp Suite** to analyze access control behavior, manipulate roles, replay sessions.
* [ ] Use **Postman** to test various roles by manually crafting requests.
* [ ] Use **ffuf/dirsearch** to find hidden directories or unprotected endpoints.
* [ ] Use **ZAP** for passive and active scanning of access issues.
* [ ] Use **JWT.io** and **jwt\_tool** to inspect, manipulate, and fuzz JWT tokens.
* [ ] Use **Autorize plugin** in Burp Suite for authorization testing automation.

---

### ✅ 10. **Manual Testing Questions**

* [ ] Can I **access another user's data** by changing a resource ID?
* [ ] Can I **modify my own role or escalate privileges** via form fields or API?
* [ ] Can I **replay old sessions** and regain access?
* [ ] Are there any **hidden admin or debug routes**?
* [ ] Can I perform actions that should require **higher privileges**?

---


