
#RahafAlqam 1232633

import argparse

from parser import parse_log_file
from reports import LogAnalyzer

# argparse: used to receive the log file name from the command line
#python main.py --report failed-login

parser = argparse.ArgumentParser()
parser.add_argument(
    "logfile",
    nargs="?",
    default="bank_server.log"
)

args = parser.parse_args()


try:
    entries, total_lines, malformed_lines = parse_log_file(args.logfile)

except FileNotFoundError:
    print("Error: Log file was not found.")
    exit()


analyzer = LogAnalyzer( #obj from class
    entries,
    total_lines,
    malformed_lines
)


while True:
    print("\nBANK LOG ANALYZER")
    print("1. Failed Login Report")
    print("2. Query Activity Summary")
    print("3. Slow Query Detector")
    print("4. Transaction Report")
    print("5. Critical Events Report")
    print("6. User Activity Report")
    print("7. Session Report")
    print("8. Events per Hour Report")
    print("9. General Log Summary")
    print("10. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        print(analyzer.failed_login_report())

    elif choice == "2":
        print(analyzer.query_activity_summary())

    elif choice == "3":
        print(analyzer.slow_query_detector())

    elif choice == "4":
        print(analyzer.transaction_report())

    elif choice == "5":
        print(analyzer.critical_events_report())

    elif choice == "6":
        username = input("Enter username: ")
        print(analyzer.user_activity_report(username))

    elif choice == "7":
        print(analyzer.session_report())

    elif choice == "8":
        print(analyzer.events_per_hour_report())

    elif choice == "9":
        print(analyzer.general_summary())

    elif choice == "10":
        print("Program ended.")
        break

    else:
        print("Invalid choice.")