# http-request-smuggler
Python script to check HTTP Request Smuggling vulnerabilities in a URL

# Description
This Python script is designed to check a given URL for request smuggling vulnerabilities. It performs a set of tests, which cover a range of known request smuggling techniques. By default, it tests for all techniques, but it can be run with a specific technique using the -t option. The script also includes error handling and an optional debug mode that prints any errors to the screen.

# Instructions
To use this script, follow these steps:

Install the required packages using the provided requirements.txt file. You can do this by running the following command: 

  pip install -r requirements.txt.

Run the script using the following command: 

  python http-request-smuggler.py -u <url> 
  
Replace <url> with the URL you want to test.

By default, the script will test for all known request smuggling techniques. You can also specify a single technique to test using the -t option. For example, to test only the CL.TE technique, you can run the following command: 

  python http-request-smuggler.py -u <url> -t CL.TE.

If you encounter any errors, you can run the script with the -d option to print them to the screen. For example: 
  
  python http-request-smuggler.py -u <url> -d.

# References
OWASP ASVS (Application Security Verification Standard) section V12.3 covers testing for request smuggling vulnerabilities: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

The PortSwigger Web Security Academy has a section on request smuggling with several labs to practice: https://portswigger.net/web-security/request-smuggling

The Common Weakness Enumeration (CWE) has an entry on request smuggling: https://cwe.mitre.org/data/definitions/444.html

The Common Attack Pattern Enumeration and Classification (CAPEC) has an entry on HTTP Request Smuggling: https://capec.mitre.org/data/definitions/33.html
