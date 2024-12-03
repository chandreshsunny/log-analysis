import re
import csv
from collections import Counter, defaultdict
FAILED_LOGIN_THRESHOLD = 10
def parse_log_file(file_path):
    """Parse the log file and extract relevant information."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = Counter()
    with open(file_path, 'r') as file:
        for line in file:
            ip_match = re.match(r'^([\d\.]+)', line)
            if not ip_match:
                continue
            ip_address = ip_match.group(1)
            status_code_match = re.search(r'"\s(\d{3})\s', line)
            status_code = int(status_code_match.group(1)) if status_code_match else None
            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE)\s(\S+)', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None
            ip_requests[ip_address] += 1
            if endpoint:
                endpoint_requests[endpoint] += 1
            if status_code == 401 or "Invalid credentials" in line:
                failed_login_attempts[ip_address] += 1
    return ip_requests, endpoint_requests, failed_login_attempts
def save_to_csv(filename, ip_requests, most_accessed_endpoint, suspicious_activity):
    """Save analysis results to a CSV file."""
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity:
            writer.writerow([ip, count])

def main():
    log_file_path = "sample.log"
    output_file_path = "log_analysis_results.csv"
    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(log_file_path)
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    suspicious_activity = [
        (ip, count) for ip, count in failed_login_attempts.items()
        if count > FAILED_LOGIN_THRESHOLD
    ]
    print("Requests per IP Address:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity:
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    save_to_csv(output_file_path, ip_requests, most_accessed_endpoint, suspicious_activity)

    print(f"\nResults saved to {output_file_path}")

if __name__ == "__main__":
    main()
