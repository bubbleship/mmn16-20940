import logging
import os
from datetime import datetime


class CSVLogger:
    """
    A CSV-based logger that writes CSV lines using only the Python logging module.
    Designed for authentication attempt logging.
    """

    def __init__(
        self,
        csv_path: str = "attempts.csv",
        fields=None,
        level=logging.INFO,
    ):
        """
        Initialize the logger.
        :param csv_path: Path to the CSV log file
        :param fields: List of fields (column names) expected for each log entry
        """
        self.csv_path = csv_path
        
        self.fields = [
            "timestamp",
            "actor",
            "action",
            "username",
            "attack_type",
            "tries",
            "details",
        ]

        # Ensure the CSV file exists and contains a header
        self._initialize_csv()

        # Create logging.Logger instance
        self.logger = logging.getLogger("CSVLogger")
        self.logger.setLevel(level)
        self.logger.propagate = False

        # File handler to append CSV lines
        handler = logging.FileHandler(self.csv_path, mode="a", encoding="utf-8")
        handler.setLevel(level)

        # CSV formatter: maps fields to CSV columns
        fmt = ",".join([f"%({f})s" for f in self.fields])
        formatter = logging.Formatter(fmt)
        handler.setFormatter(formatter)

        # Attach handler if none already exists
        if not self.logger.handlers:
            self.logger.addHandler(handler)
            
            
            
            

    # ------------------------------------------------
    # Internal: Create CSV with header if missing
    # ------------------------------------------------
    def _initialize_csv(self):
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", encoding="utf-8") as f:
                f.write(",".join(self.fields) + "\n")

    # ------------------------------------------------
    # Public: Log a structured entry
    # ------------------------------------------------
    def log(self, **kwargs):
        """
        Log a single CSV row.
        Missing fields are filled as empty strings.
        """

        # Auto-generate timestamp if missing
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.utcnow().isoformat()

        # Fill missing fields and convert everything to string
        record = {field: str(kwargs.get(field, "")) for field in self.fields}

        # Write CSV line
        self.logger.info("", extra=record)

    # ------------------------------------------------
    # Clear logs and recreate header
    # ------------------------------------------------
    def clear(self):
        """Erase existing logs and recreate the CSV header."""
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(",".join(self.fields) + "\n")
