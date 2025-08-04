## ✅ **Insecure Design Checklist (Offensive Security Focused)**

### 🔍 1. **Authentication and Authorization Design**

* [ ] Are there **design flaws** in how user sessions are created, validated, and terminated?
* [ ] Does the app **mix authentication and authorization logic**?
* [ ] Can you escalate privileges by **tampering with roles or access levels** in tokens, headers, or requests?
* [ ] Are there **no defined security requirements** in design documents?
* [ ] Is **role-based access control (RBAC)** missing or poorly implemented?

> 🛠 Try manipulating session tokens, JWTs, or user roles directly in requests.

---

### 🔐 2. **Trust Boundary Mismanagement**

* [ ] Are **internal APIs exposed** to untrusted environments?
* [ ] Is **client-side input** trusted by backend processes without validation?
* [ ] Can you **forge internal requests** (SSRF, Insecure Direct Object References)?
* [ ] Is there a **lack of segmentation between services** (e.g., frontend/backend)?

> 🛠 Attempt lateral movement by accessing endpoints outside your scope.

---

### 📉 3. **Lack of Secure Development Principles**

* [ ] Are security best practices (e.g., principle of least privilege, fail-safe defaults) ignored in the code logic?
* [ ] Are security controls added as an afterthought instead of baked into design?
* [ ] Does the application **lack threat modeling documentation**?
* [ ] Is input validation **not centralized**, making bypass easier?

> 🛠 Check for inconsistent validation logic or insecure libraries across modules.

---

### 🔄 4. **Improper State Machine Logic**

* [ ] Can the application be forced into an **invalid state** through crafted sequences (e.g., skipping payment steps)?
* [ ] Are there **missing or flawed preconditions** in business logic flow?
* [ ] Are unauthorized actions **allowed by default** under certain conditions?

> 🛠 Fuzz for state transitions, bypassing logical flow using tools like Burp Suite’s Repeater and Sequencer.

---

### 📦 5. **Missing Design for Threat Scenarios**

* [ ] Does the system lack **countermeasures** for common threat scenarios (e.g., replay attacks, race conditions)?
* [ ] Are **rate-limiting**, **retries**, and **timeouts** handled poorly or missing?
* [ ] Is **logging and alerting** for anomalous behavior absent?

> 🛠 Attempt brute force, DoS, or abuse flows with automated tools.

---

### 📤 6. **Client-Side Trust Assumptions**

* [ ] Are **critical decisions made on the client side** (e.g., pricing, logic enforcement)?
* [ ] Can you manipulate **client-side JavaScript or mobile apps** to gain unauthorized features?
* [ ] Is **debug information** left in production JS files or APKs?

> 🛠 Reverse engineer or tamper with client apps/scripts using tools like Frida, MobSF, or browser dev tools.

---

### 🛡️ 7. **Inadequate Cryptographic Design**

* [ ] Is encryption handled manually without using **proven libraries**?
* [ ] Is there **no separation between encrypted and non-encrypted data flows**?
* [ ] Are keys **hardcoded** or **not rotated**?

> 🛠 Try leaking keys, weak encryption modes, or decrypting data.

---

### 🕵️ 8. **Security Features Disabled for UX**

* [ ] Are important security features like 2FA, CSRF protection, etc. **disabled or made optional**?
* [ ] Is **error handling** verbose, revealing internal design or stack traces?

> 🛠 Trigger validation and error messages to reveal backend structure.

---

### ⚠️ 9. **Improper Use of Third-Party Components**

* [ ] Are third-party libraries used without **security vetting**?
* [ ] Are outdated or **vulnerable dependencies present**?
* [ ] Is open-source software used with **insecure default configurations**?

> 🛠 Run tools like Trivy or Syft to identify vulnerable components.

---

### 🔐 10. **Checklist for Exploitation Paths (Red Team View)**

* [ ] Can you **simulate logical flaws** (e.g., ordering free items, skipping approvals)?
* [ ] Can you escalate to **admin-level or system-level** via design gaps?
* [ ] Can you **bypass business rules** or process flows?
* [ ] Can you identify **data exposure paths** via poor architecture?

---

## 📌 Bonus Offensive Tools for Insecure Design Testing:

* **Burp Suite Pro** – for fuzzing flows and analyzing request/response chains.
* **OWASP ZAP** – automated scanning and logic flaw testing.
* **Postman** – simulate crafted API flows.
* **Mitmproxy** – analyze and manipulate traffic between components.
* **Threat Dragon / IriusRisk** – visualize and exploit threat models.

---
