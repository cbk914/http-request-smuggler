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

By default, the script will test for all known request smuggling techniques. You can also specify a single technique to test using the -t option. For example, to test only the CLTE technique, you can run the following command: 

  python http-request-smuggler.py -u <url> -t CLTE

If you encounter any errors, you can run the script with the -d option to print them to the screen. For example: 
  
  python http-request-smuggler.py -u <url> -d

# References
OWASP ASVS (Application Security Verification Standard) section V12.3 covers testing for request smuggling vulnerabilities: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

The PortSwigger Web Security Academy has a section on request smuggling with several labs to practice: https://portswigger.net/web-security/request-smuggling

The Common Weakness Enumeration (CWE) has an entry on request smuggling: https://cwe.mitre.org/data/definitions/444.html

The Common Attack Pattern Enumeration and Classification (CAPEC) has an entry on HTTP Request Smuggling: https://capec.mitre.org/data/definitions/33.html


# client-side-desync
This Python script checks for client-side desync vulnerabilities by sending a GET request to the specified URL and checking the response headers. If both the Transfer-Encoding and Content-Length headers are present in the response, this indicates a potential client-side desync vulnerability. The script also includes a debugging option to print the response content and headers for further analysis.

# Instructions
Run the script using the following command:

  python client-side-desync -u <URL> [-d]

Replace <URL> with the URL you want to check for client-side desync vulnerabilities. The -d option is optional and will print the response content and headers for debugging purposes.

For example, to check the URL https://example.com and print debugging information, you would run the following command:

  python client-side-desync.py -u https://example.com -d

The script will send a GET request to the specified URL and check the response headers for client-side desync vulnerabilities. If a vulnerability is found, it will print a warning message. If no vulnerability is found, it will print a message indicating that no vulnerability was detected.

If the -d option was used, the script will also print the response content and headers for further analysis.

Note that if an error occurs during the execution of the script (such as a network error or invalid URL), an error message will be printed and the script will exit.

# References

[HTTP Desync Attacks: Request Smuggling Reborn:](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) A comprehensive guide to HTTP desync attacks, which can result in client-side desynchronization vulnerabilities.

[Desync Attacks in HTTP/2:](https://portswigger.net/research/desync-attacks-in-http-2) A research article about desync attacks in HTTP/2, which can also result in client-side desynchronization vulnerabilities.  

[CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CAPEC-105: HTTP Request Splitting](https://capec.mitre.org/data/definitions/105.html)  
  
[OWASP ASVS: HTTP Request Splitting:](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) 
