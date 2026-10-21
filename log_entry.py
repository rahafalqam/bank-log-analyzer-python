from dataclasses import dataclass
from datetime import datetime

# dataclasses: used to create the LogEntry data class and automatically generate its constructor
# datetime is used to convert timestamps and calculate session duration

@dataclass
class LogEntry:

    timestamp: datetime
    level: str
    session_id: str
    user: str
    client_ip: str
    module: str
    message: str