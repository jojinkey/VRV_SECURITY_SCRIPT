import re
import csv
from collections import defaultdict
import os
import threading
import time

# File paths c:/Users/jalaj/VsCodeLiter/PYs/VRV/
log_file = "sample.log"
output_csv = "log_analysis_results.csv"

# Default configuration
DEFAULT_FAILED_LOGIN_THRESHOLD = 5

# Global variable to manage input timeout
user_input_value = None


def timeout_input(prompt, timeout, default):
    global user_input_value

    def user_input_thread():
        global user_input_value
        user_input_value = input(prompt)

    thread = threading.Thread(target=user_input_thread)
    thread.daemon = True
    thread.start()

    thread.join(timeout)
    if thread.is_alive():  # If timeout occurs
        print(f"\nNo input received within {timeout} seconds. Using default: {default}")
        return default

    return int(user_input_value) if user_input_value.isdigit() else default


def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_hits = defaultdict(int)
    failed_logins = defaultdict(int)

    # Check if the file exists before trying to open it
    if not os.path.exists(file_path):
        print(f"Error: The log file at {file_path} does not exist.")
        exit(1)

    with open(file_path, 'r') as file:
        logs = file.readlines()

    for line in logs:
        # Extract IP address
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            ip = ip_match.group(1)
            ip_requests[ip] += 1

        # Extract endpoint
        endpoint_match = re.search(r'\"[A-Z]+\s+(\S+)\s+HTTP', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_hits[endpoint] += 1

        # Detect failed logins (based on HTTP 401 or failure message)
        if "401" in line or "Invalid credentials" in line:
            if ip_match:
                ip = ip_match.group(1)  # Ensure the IP is extracted for failed attempts
                failed_logins[ip] += 1

    return ip_requests, endpoint_hits, failed_logins


def find_most_accessed_endpoint(endpoint_hits):
    if endpoint_hits:
        return max(endpoint_hits.items(), key=lambda x: x[1])
    return None, 0


def find_suspicious_ips(failed_logins, threshold):
    return {ip: count for ip, count in failed_logins.items() if count > threshold}


def write_to_csv(output_path, ip_requests, most_accessed_endpoint, suspicious_ips):
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP Requests
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def main():
    # Ask the user for the failed login threshold
    print("Configure Suspicious Activity Threshold")
    print("You have 4 seconds to enter a value or the default of 5 will be used.")
    threshold = timeout_input("Enter the failed login attempt threshold: ", 4, DEFAULT_FAILED_LOGIN_THRESHOLD)

    # Parse the log file
    ip_requests, endpoint_hits, failed_logins = parse_log_file(log_file)

    # Find the most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_hits)

    # Detect suspicious activity
    suspicious_ips = find_suspicious_ips(failed_logins, threshold)

    # Print results
    print("\nIP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Write results to CSV
    write_to_csv(output_csv, ip_requests, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults have been saved to {output_csv}")


if __name__ == "__main__":
    main()
