"""Recon Type Ontology and Port Data Types."""

from enum import Enum


class DataType(str, Enum):
    """Strongly-typed data ontology for inter-node contracts."""
    TARGET_DOMAIN = "TargetDomain"
    FQDN = "FQDN"
    IP_ADDRESS = "IPAddress"
    NETWORK_CIDR = "NetworkCIDR"
    ASN = "ASN"
    HTTP_URL = "HTTPUrl"
    PORT_SERVICE = "PortService"
    FINDING = "Finding"
    FILE = "File"
    RAW_TEXT = "RawText"

    @classmethod
    def is_compatible(cls, source_type: "DataType", target_type: "DataType") -> bool:
        """Determines if source output can flow into target input directly or via safe coercion."""
        if source_type == target_type:
            return True
        
        # Universal sinks
        if target_type in (cls.FILE, cls.RAW_TEXT):
            return True

        # TargetDomain is a valid FQDN
        if source_type == cls.TARGET_DOMAIN and target_type == cls.FQDN:
            return True

        # FQDN or IP can be coerced into HTTPUrl by protocol prefixing
        if source_type in (cls.FQDN, cls.IP_ADDRESS) and target_type == cls.HTTP_URL:
            return True

        return False
