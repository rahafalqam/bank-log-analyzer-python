import re
import logging

from datetime import datetime
from log_entry import LogEntry


# re is used to divide each log line into its fields
# logging is used to record invalid log lines


logging.basicConfig(  #when s.th wrong
    level=logging.WARNING,
    format="%(levelname)s: %(message)s"
)


# This pattern divides each log line into seven named fields

LOG_PATTERN = (
    r"^\[(?P<timestamp>.*?)\] "
    r"\[(?P<level>.*?)\] "
    r"\[(?P<session_id>.*?)\] "
    r"\[(?P<user>.*?)\] "
    r"\[(?P<client_ip>.*?)\] "
    r"\[(?P<module>.*?)\] - "
    r"(?P<message>.*)$"
)


# from log file to LogEntry
def parse_log_line(line, line_number):

    line = line.strip() #remove space and enter from start and end

    if line == "":
        return None

    match = re.match(LOG_PATTERN, line)

    if match:
        try:
            timestamp = datetime.strptime( #form string to datetime
                match.group("timestamp"),
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:
            logging.warning(
                "Invalid timestamp in line number %d",
                line_number
            )
            return None

        entry = LogEntry( #acording to our class 
            timestamp,
            match.group("level"),
            match.group("session_id"),
            match.group("user"),
            match.group("client_ip"),
            match.group("module"),
            match.group("message")
        )

        return entry

    else:
        logging.warning(
            "Invalid log line number %d",
            line_number
        )
        return None


def parse_log_file(file_name):
    """Read the log file and return the parsed information."""

    entries = []
    total_lines = 0
    malformed_lines = 0

    log_file = open(file_name, "r")

    for line in log_file:
        total_lines = total_lines + 1

        if line.strip() != "":
            entry = parse_log_line(
                line,
                total_lines
            )

            if entry:
                entries.append(entry)

            else:
                malformed_lines = malformed_lines + 1

    log_file.close()

    return entries, total_lines, malformed_lines