import enum


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ThreatLevel(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"


class UserRole(str, enum.Enum):
    REGULAR = "REGULAR"
    COMPANY_EMPLOYEE = "COMPANY_EMPLOYEE"
