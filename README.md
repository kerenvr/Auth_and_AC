# Auth_and_AC
Project: Authentication and Access Control System with Secure Design Principles

Overview

In this project, you will create a simple authentication and access control system using Python. The goal is to implement mechanisms that manage user authentication and file access, ensuring that only authorized users can access specific resources. Additionally, you must specify which secure design principles (from Saltzer and Schroeder's principles, OWASP, and other secure design resources) you employed for each mechanism in your program.

Objective
•	Design and implement a Python-based system that includes user account creation, authentication, secure password storage (with hashing), and access control mechanisms.
•	For each major component of your system, document and explain which secure design principles you applied and why.
•	You will need to refactor your crypto_project.py file into a new file CryptoProject.py that creates a CryptoProject as a class.  You will import this into your new program and use its methods to accomplish the cryptographic functions of the new program.

Requirements

0. Refactor crypto_project:
•	Refactor your crypto_project.py into CryptoProject.py.
•	Convert your existing functions into methods of a class that can be instantiated and used as an object.
•	
What You Need to Do:
1.	Use the included Python file CryptoProject.py.
2.	A class is already defined called CryptoProject.
3.	Move your functions from crypto_project.py into the new class as methods. These methods should be copied and pasted from their related function in crypto_project.py.
4.	The necessary imports are already added for you 
5.	Test your class to ensure that each method still works as expected when called from an instance of the class.





1. User Authentication
•	Implement user registration where users can create accounts with a username and a password.
•	Store passwords securely using the hash_string() and verify_integrity() methods from your CryptoProject.py
•	Implement user login functionality where users can authenticate by entering their credentials.
Secure Design Principles to Consider:
•	Least Privilege: Limit the scope of what an authenticated user can do by default.
•	Fail-Safe Defaults: Ensure that users who are not logged in or do not have permission are denied access.
•	Psychological Acceptability: Ensure that the login process is user-friendly without compromising security.

2. File Access Control
•	Ensure that users can only access files for which they have the appropriate permissions.
•	Implement access control lists (ACLs) or another method to specify which files each user or role can access.
Secure Design Principles to Consider:
•	Fail-Safe Defaults: Deny access to files by default, and only grant access based on explicit permissions.
•	Open Design: Make sure the security of the system does not rely on keeping the implementation secret but instead on solid, well-designed access control mechanisms.

3. Bonus: File Encryption (Optional)
•	Implement file encryption for sensitive data (using AES or RSA).
•	Ensure proper key management so that only authorized users can decrypt the data.
Secure Design Principles to Consider:
•	Defense in Depth: Use encryption as an additional layer of security to protect sensitive data.
•	Least Common Mechanism: Avoid sharing encryption keys across all users; each user or role should have distinct access keys.


Submission Instructions

•	Code: Submit your Python code with all required functionality (authentication, access control, etc.).
•	Documentation: For each mechanism (e.g., password hashing, access control lists), provide a section in your report explaining:
1.	What you implemented (e.g., "I used bcrypt to hash passwords").
2.	Which secure design principle(s) you followed (e.g., "This follows the Principle of Least Privilege because...").
3.	How your implementation addresses security concerns (e.g., "Hashing passwords ensures they are not stored in plaintext, which mitigates risks of data breaches").

Grading Criteria
•	Functionality (60%): Does the system work as expected (correctly handles authentication, access control, etc.)?
•	Security (20%): Are secure design principles properly implemented? Are there any glaring security issues (e.g., passwords stored in plaintext)?
•	Documentation (20%): Does the documentation clearly explain the design choices and the secure design principles used?

File Downloads
You can use the following framework files downloadable on Cavas as a starting point for your project:
•	AAC_CryptoClass_Framework.py
•	Auth_and_AC.py

![image](https://github.com/user-attachments/assets/72861da9-0fb1-4326-9a64-a5a73d8db562)
