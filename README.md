# mikrotik-userman-xss
Reflected XSS in MikroTik RouterOS UserManager Web Interface
# Exploit Title: MikroTik RouterOS < v7 - Reflected Cross-Site Scripting (XSS) in UserManager Web Interface
# Google Dork: N/A (UserManager interface is typically not publicly exposed)
# Date: 2025-07-03
# Exploit Author: Ahmed Mutaher
# Vendor Homepage: https://mikrotik.com/
# Software Link: https://mikrotik.com/download
# Version: All versions prior to v7.0
# Tested on:
#   - RB1100AHx4 (v6.48.2)
#   - RB750GL (v6.39)
#   - CCR1009-8G-1S-1S+ (v6.41)
#   - x86 (v5.20, v6.49.18)
# CVE: N/A

# Description:
# A reflected cross-site scripting (XSS) vulnerability exists in MikroTik RouterOS versions prior to v7,
# specifically in the UserManager web interface. This flaw can be exploited by unauthenticated attackers,
# allowing JavaScript injection via a specially crafted URL without requiring a valid login session.
#
# During analysis of the source code of the /userman page, it was discovered that the application attempts
# to mitigate input by discarding any content after the double slash (//). However, by repeating the payload
# and crafting it carefully, this behavior can be bypassed and JavaScript can be executed in the browser context.

# Vulnerable Endpoint:
# http://<router-ip>/userman/',true);alert('XSS');//',true);alert('XSS');//

# Proof of Concept (PoC):
Payload:
http://192.168.88.1/userman/',true);alert('XSS');//',true);alert('XSS');//

# Steps to Reproduce:
1. Open the target RouterOS UserManager URL in a browser without logging in.
2. Inspect the page source and identify the reflected input behavior.
3. Notice that the system strips content after `//`.
4. Craft the payload to repeat the malicious code to bypass the filtering.
5. When the payload is executed, an alert box is triggered, proving the XSS vulnerability.

# Impact:
- JavaScript execution without authentication.
- Possible phishing or redirection attacks.
- Can be used as part of a social engineering chain to trick admins or users.

# Mitigation:
- Sanitize all user input using context-aware encoding (e.g., htmlspecialchars()).
- Implement Content Security Policy (CSP).
- Avoid reflecting unsanitized GET parameters in HTML or JavaScript contexts.
