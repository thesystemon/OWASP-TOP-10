
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

