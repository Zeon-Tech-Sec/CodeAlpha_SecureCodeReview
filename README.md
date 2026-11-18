# CodeAlpha_SecureCodeReview
A security review of an open-source Flask app, done for my CodeAlpha Cyber Security internship. I found 12 issues, 4 of them critical, including SQL injection, unsafe YAML loading and a broken login token check. Each one has line numbers, a fix and a test. Bandit caught only half, so the rest came from reading the code.
