import subprocess
from termcolor import colored

# List of techniques
techniques = ["CLTE", "CL.0", "SLRE", "TECL", "TESI"]

# Open the file with URLs
with open('targets.txt', 'r') as file:
    urls = file.read().splitlines()

# Loop over each URL
for url in urls:
    # Loop over each technique
    for tech in techniques:
        # Construct the command
        command = f"python3 http-request-smuggler.py -t {tech} -u https://{url}"
        
        # Print the URL being scanned
        print(colored(f"Scanning {url} with technique {tech}...", 'blue'))

        # Run the command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Decode the output
        stdout = stdout.decode()
        stderr = stderr.decode()

        # Determine the color for the output
        color = 'green' if 'error' not in stdout.lower() and 'error' not in stderr.lower() else 'red'

        # Print the output
        print(colored(stdout, color))
        print(colored(stderr, color))

