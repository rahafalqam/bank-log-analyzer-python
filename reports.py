class LogAnalyzer:
    """Contains all log analysis services."""

    def __init__(self, entries, total_lines, malformed_lines):
        self.entries = entries
        self.total_lines = total_lines
        self.malformed_lines = malformed_lines



    # Service 1: Failed Login Report
    def failed_login_report(self):

        total_failed = 0
        failed_by_ip = {}
        failed_by_user = {}

        for entry in self.entries:

            if (
                entry.module == "AUTH"
                and entry.level == "ERROR"
                and "failed login attempt" in entry.message.lower()
            ):
                total_failed = total_failed + 1

                if entry.client_ip in failed_by_ip:
                    failed_by_ip[entry.client_ip] = (
                        failed_by_ip[entry.client_ip] + 1
                    )
                else:
                    failed_by_ip[entry.client_ip] = 1

                if entry.user in failed_by_user:
                    failed_by_user[entry.user] = (
                        failed_by_user[entry.user] + 1
                    )
                else:
                    failed_by_user[entry.user] = 1

        report = "\nFAILED LOGIN REPORT\n"
        report = report + "Total failed attempts: "
        report = report + str(total_failed) + "\n"

        report = report + "\nFailed attempts by IP:\n"

        if len(failed_by_ip) == 0:
            report = report + "No failed login attempts found.\n"

        else:
            for client_ip in sorted(failed_by_ip):
                count = failed_by_ip[client_ip]

                report = report + client_ip
                report = report + ": " + str(count)

                if count >= 3:
                    report = report + " [Possible brute-force source]"

                report = report + "\n"

        report = report + "\nFailed attempts by user:\n"

        if len(failed_by_user) == 0:
            report = report + "No failed login attempts found.\n"

        else:
            for user in sorted(failed_by_user):
                count = failed_by_user[user]

                report = report + user
                report = report + ": " + str(count) + "\n"

        return report



    # Service 2: Query Activity Summary
    def query_activity_summary(self):

        total_queries = 0

        query_types = {
            "SELECT": 0,
            "INSERT": 0,
            "UPDATE": 0,
            "DELETE": 0
        }

        for entry in self.entries:

            if entry.module == "QUERY":
                total_queries = total_queries + 1

                message = entry.message.upper()

                if "SELECT" in message:
                    query_types["SELECT"] = (
                        query_types["SELECT"] + 1
                    )

                elif "INSERT" in message:
                    query_types["INSERT"] = (
                        query_types["INSERT"] + 1
                    )

                elif "UPDATE" in message:
                    query_types["UPDATE"] = (
                        query_types["UPDATE"] + 1
                    )

                elif "DELETE" in message:
                    query_types["DELETE"] = (
                        query_types["DELETE"] + 1
                    )

        report = "\nQUERY ACTIVITY SUMMARY\n"
        report = report + "Total query events: "
        report = report + str(total_queries) + "\n\n"
        report = report + "Queries by type:\n"

        for query_type in query_types:
            report = report + query_type
            report = report + ": "
            report = report + str(query_types[query_type])
            report = report + "\n"

        return report



    # Service 3: Slow Query Detector
    def slow_query_detector(self):

        slow_queries = []

        for entry in self.entries:

            if (
                entry.module == "QUERY"
                and entry.level == "WARNING"
                and "slow" in entry.message.lower()
            ):
                execution_time = "Not available"
                words = entry.message.split()

                for index in range(len(words)):

                    if (
                        words[index].lower() == "in"
                        and index + 2 < len(words) #take a two words after "in" as ex. time
                    ):
                        execution_time = (
                            words[index + 1]
                            + " "
                            + words[index + 2]
                        )
                        break

                slow_queries.append(
                    [entry, execution_time]
                )

        report = "\nSLOW QUERY DETECTOR\n"

        if len(slow_queries) == 0:
            report = report + "No slow queries found.\n"

        else:
            report = report + "Total slow queries: "
            report = report + str(len(slow_queries))
            report = report + "\n\n"

            for slow_query in slow_queries:

                entry = slow_query[0]
                execution_time = slow_query[1]

                report = report + str(entry.timestamp)
                report = report + " | User: "
                report = report + entry.user
                report = report + " | Execution time: "
                report = report + execution_time
                report = report + " | Query: "
                report = report + entry.message
                report = report + "\n"

        return report



    # 4: Transaction Report
    def transaction_report(self):

        deposits = 0
        withdrawals = 0
        declined = 0
        rollbacks = 0

        total_deposited = 0.0
        total_withdrawn = 0.0

        for entry in self.entries:

            if entry.module == "TRANSACTION":

                message = entry.message.lower()
                words = entry.message.split()

                if "deposit" in message:
                    deposits = deposits + 1

                    for word in words:
                        try:
                            amount = float(word)
                            total_deposited = (
                                total_deposited + amount
                            )
                            break

                        except ValueError:
                            pass

                elif "withdraw" in message:
                    withdrawals = withdrawals + 1

                    for word in words:
                        try:
                            amount = float(word)
                            total_withdrawn = (
                                total_withdrawn + amount
                            )
                            break

                        except ValueError:
                            pass

                if "declined" in message:
                    declined = declined + 1

                if "rollback" in message:
                    rollbacks = rollbacks + 1

        report = "\nTRANSACTION REPORT\n"

        report = report + "Deposits: "
        report = report + str(deposits) + "\n"

        report = report + "Withdrawals: "
        report = report + str(withdrawals) + "\n"

        report = report + "Declined transactions: "
        report = report + str(declined) + "\n"

        report = report + "Rollbacks: "
        report = report + str(rollbacks) + "\n"

        report = report + "Total deposited amount: "
        report = report + str(total_deposited) + "\n"

        report = report + "Total withdrawn amount: "
        report = report + str(total_withdrawn) + "\n"

        return report



    # 5: Critical Events Report
    def critical_events_report(self):

        critical_count = 0
        critical_details = ""

        for entry in self.entries:

            if entry.level == "CRITICAL":
                critical_count = critical_count + 1

                critical_details = (
                    critical_details
                    + str(entry.timestamp)
                    + " | "
                    + entry.message
                    + "\n"
                )

        report = "\nCRITICAL EVENTS REPORT\n"
        report = report + "Total critical events: "
        report = report + str(critical_count) + "\n\n"

        if critical_count == 0:
            report = report + "No critical events found.\n"

        else:
            report = report + critical_details

        return report



    # 6: User Activity Report
    def user_activity_report(self, username):

        user_entries = []

        for entry in self.entries:

            if entry.user.lower() == username.lower():
                user_entries.append(entry)

        report = "\nUSER ACTIVITY REPORT\n"
        report = report + "Username: "
        report = report + username + "\n\n"

        if len(user_entries) == 0:
            report = report + "Username not found.\n"

        else:
            for entry in user_entries:
                report = report + str(entry.timestamp)
                report = report + " | "
                report = report + entry.module
                report = report + " | "
                report = report + entry.message
                report = report + "\n"

        return report



    # 7: Login and Logout Session Report
   # Service 7: Login and Logout Session Report
    def session_report(self):

        sessions = {}

        for entry in self.entries:

           
            if entry.session_id not in sessions:
                sessions[entry.session_id] = { #make session if it does not exist
                    "user": entry.user,
                    "login_time": "",
                    "logout_time": ""
                }

            message = entry.message.lower()

        
            if (
                entry.module == "AUTH"
                and "login" in message
                and "failed" not in message
            ):
                sessions[entry.session_id]["user"] = entry.user
                sessions[entry.session_id]["login_time"] = entry.timestamp

            elif (
                entry.module == "AUTH"
                and "logout" in message
            ):
                sessions[entry.session_id]["user"] = entry.user
                sessions[entry.session_id]["logout_time"] = entry.timestamp


        report = "\nLOGIN/LOGOUT SESSION REPORT\n"


        if len(sessions) == 0:

            report = report + "No session activity found.\n"

        else:

            for session_id in sorted(sessions):

                session = sessions[session_id]

                report = report + session_id + "\n"

                report = report + "  User: "
                report = report + session["user"] + "\n"


                report = report + "  Login time: "

                if session["login_time"]:
                    report = report + str(session["login_time"]) + "\n"
                else:
                    report = report + "Not available\n"


                report = report + "  Logout time: "

                if session["logout_time"]:
                    report = report + str(session["logout_time"]) + "\n"
                else:
                    report = report + "Not available\n"


                report = report + "  Duration: "

                if (
                    session["login_time"]
                    and session["logout_time"]
                ):

                    duration = (
                        session["logout_time"]
                        - session["login_time"]
                    )

                    report = report + str(duration) + "\n"

                else:

                    report = report + "Not available\n"


                report = report + "\n"


        return report



    #  8: Events per Hour Report
    def events_per_hour_report(self):

        events_by_hour = {}

        for entry in self.entries:

            hour = entry.timestamp.hour #take only hours

            if hour in events_by_hour:
                events_by_hour[hour] = (
                    events_by_hour[hour] + 1
                )

            else:
                events_by_hour[hour] = 1

        report = "\nEVENTS-PER-HOUR REPORT\n"

        if len(events_by_hour) == 0:
            report = report + "No events found.\n"

        else:
            for hour in sorted(events_by_hour):

                count = events_by_hour[hour]

                if hour < 10:
                    hour_text = "0" + str(hour) + ":00"

                else:
                    hour_text = str(hour) + ":00"

                report = report + hour_text
                report = report + " | Events: "
                report = report + str(count) + "\n"

        return report



    #  9: General Log Summary
    def general_summary(self):

        level_counts = {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "CRITICAL": 0
        }

        module_counts = {}

        for entry in self.entries:

            if entry.level in level_counts:
                level_counts[entry.level] = (
                    level_counts[entry.level] + 1
                )

            if entry.module in module_counts:
                module_counts[entry.module] = (
                    module_counts[entry.module] + 1
                )

            else:
                module_counts[entry.module] = 1

        busiest_module = "N/A"
        highest_count = 0

        for module in module_counts:

            if module_counts[module] > highest_count:
                highest_count = module_counts[module]
                busiest_module = module

        report = "\nGENERAL LOG SUMMARY\n"

        report = report + "Total lines: "
        report = report + str(self.total_lines) + "\n"

        report = report + "Valid entries: "
        report = report + str(len(self.entries)) + "\n"

        report = report + "Malformed lines: "
        report = report + str(self.malformed_lines) + "\n"

        report = report + "\nEvents by log level:\n"

        report = report + "INFO: "
        report = report + str(level_counts["INFO"]) + "\n"

        report = report + "WARNING: "
        report = report + str(level_counts["WARNING"]) + "\n"

        report = report + "ERROR: "
        report = report + str(level_counts["ERROR"]) + "\n"

        report = report + "CRITICAL: "
        report = report + str(level_counts["CRITICAL"]) + "\n"

        report = report + "\nBusiest module: "
        report = report + busiest_module

        if busiest_module != "N/A":
            report = report + " ("
            report = report + str(highest_count)
            report = report + " events)"

        report = report + "\n"

        return report