# Entity extraction: the accounts, hosts, addresses and objects an event talks
# about. Rules and the timeline both lean on this, so the parsing of addresses
# and the classification of private space lives in one place.

import re

# dotted quad, deliberately strict so version strings are not mistaken for hosts
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# a windows path, used to pull the image name out of command lines
WINDOWS_PATH = re.compile(r"[A-Za-z]:\\\\?[^\s\"']+|\\\\\\\\[^\s\"']+")
# account references such as DOMAIN\\user or user@domain
ACCOUNT = re.compile(r"\b([A-Za-z0-9._-]+)\\\\([A-Za-z0-9._$-]+)|\b([A-Za-z0-9._%-]+@[A-Za-z0-9.-]+)")
# administrative shares are a strong lateral movement signal
ADMIN_SHARE = re.compile(r"\\\\(?:[^\\]+)\\(ADMIN\$|C\$|IPC\$|print\$)", re.IGNORECASE)

# fields whose values are worth scanning for addresses
ADDRESS_FIELDS = ("IpAddress", "SourceAddress", "DestinationAddress", "ClientAddress", "RemoteAddress", "Address", "ServiceAddress")


def is_private(address):
    # rfc1918, loopback and link local space, the addresses that never leave a network
    parts = address.split(".")
    if len(parts) != 4:
        return False
    first, second = int(parts[0]), int(parts[1])
    if first == 10 or first == 127:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 169 and second == 254:
        return True
    return False


class Entities:
    # the running set of things seen in the logs, filled in as events are read
    __slots__ = ("accounts", "hosts", "addresses", "private_addresses", "processes", "services", "tasks", "domains", "logon_ids", "shares", "objects")

    def __init__(self):
        self.accounts = set()
        self.hosts = set()
        self.addresses = set()
        self.private_addresses = set()
        self.processes = set()
        self.services = set()
        self.tasks = set()
        self.domains = set()
        self.logon_ids = set()
        self.shares = set()
        self.objects = set()

    def add_account(self, value):
        text = (value or "").strip()
        if not text or text == "-":
            return
        self.accounts.add(text)
        if "\\" in text:
            self.domains.add(text.split("\\")[0])

    def add_address(self, value):
        text = (value or "").strip()
        if not text or text == "-":
            return
        for candidate in IPV4.findall(text):
            self.addresses.add(candidate)
            if is_private(candidate):
                self.private_addresses.add(candidate)

    def add_host(self, value):
        text = (value or "").strip().rstrip("$")
        if text and text != "-":
            self.hosts.add(text)

    def add_process(self, value):
        text = (value or "").strip()
        if not text or text == "-":
            return
        match = WINDOWS_PATH.search(text)
        name = match.group(0) if match else text
        self.processes.add(name.replace("\\\\", "\\"))

    def add_share(self, value):
        text = (value or "").strip()
        if text and text != "-":
            self.shares.add(text)

    def counts(self):
        return {
            "accounts": len(self.accounts),
            "hosts": len(self.hosts),
            "addresses": len(self.addresses),
            "processes": len(self.processes),
            "services": len(self.services),
            "tasks": len(self.tasks),
            "shares": len(self.shares),
        }

    def as_dict(self):
        return {
            "accounts": sorted(self.accounts),
            "hosts": sorted(self.hosts),
            "addresses": sorted(self.addresses),
            "private_addresses": sorted(self.private_addresses),
            "processes": sorted(self.processes),
            "services": sorted(self.services),
            "tasks": sorted(self.tasks),
            "domains": sorted(self.domains),
            "shares": sorted(self.shares),
        }


def harvest(event, entities):
    # pull every identifier an event carries into the running entity sets
    # the computer a record came from is a host, not an account
    entities.add_host(event.computer)
    entities.add_account(event.user_id)
    for key, value in event.payload.items():
        if not value:
            continue
        lowered = key.lower()
        if lowered in ("ipaddress", "ip_port") or lowered.endswith("address"):
            entities.add_address(value)
        elif lowered in ("workstationname", "targetservername", "computername"):
            entities.add_host(value)
        elif lowered in ("newprocessname", "processname", "parentprocessname", "imagepath", "servicename", "servicestartname", "imagename"):
            entities.add_process(value)
        elif lowered in ("servicename", "servicestartname"):
            entities.services.add(value)
        elif "taskname" in lowered:
            entities.tasks.add(value)
        elif lowered in ("subjectusername", "targetusername", "accountname", "username", "param1", "param2"):
            entities.add_account(value)
        elif lowered in ("sharename", "sharelocalpath"):
            entities.add_share(value)
        elif "logonid" in lowered:
            entities.logon_ids.add(value)
        elif lowered.startswith("objectname"):
            entities.objects.add(value)
        else:
            for candidate in IPV4.findall(value):
                # addresses can hide inside free text such as command lines
                entities.addresses.add(candidate)
                if is_private(candidate):
                    entities.private_addresses.add(candidate)
    for match in ACCOUNT.finditer(event.searchable_text()):
        if match.group(2):
            entities.add_account("%s\\%s" % (match.group(1), match.group(2)))
        elif match.group(3):
            entities.add_account(match.group(3))


def attack_surface(event):
    # flags on an event that make it worth a look even without a rule
    notes = []
    text = event.searchable_text()
    if ADMIN_SHARE.search(text):
        notes.append("administrative share referenced")
    return notes
