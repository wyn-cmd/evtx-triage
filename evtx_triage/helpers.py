# Time and size helpers shared by the parser and the reports. FILETIME values
# count 100 nanosecond ticks from 1601-01-01, and everything here is done with
# integer arithmetic so dates far from the unix epoch keep full precision.

from datetime import datetime, timedelta

# ticks between the FILETIME epoch and the unix epoch
FILETIME_EPOCH_DELTA_US = 11644473600000000
FILETIME_EPOCH = datetime(1601, 1, 1)
UNIX_EPOCH = datetime(1970, 1, 1)


def filetime_to_datetime(value):
    # a zero FILETIME means "not set" in Windows, reported as None here
    if not value:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None


def datetime_to_filetime(moment):
    # inverse of filetime_to_datetime, used by the test fixture writer
    if moment is None:
        return 0
    delta = moment - FILETIME_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10 ** 7 + delta.microseconds * 10


def isoformat(moment):
    # same rendering as datetime.isoformat(" "), microseconds only when non zero
    if moment is None:
        return ""
    text = "%04d-%02d-%02d %02d:%02d:%02d" % (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second)
    if moment.microsecond:
        text += ".%06d" % moment.microsecond
    return text


def format_bytes(value):
    # human readable byte counts for reports
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    index = 0
    while size >= 1024.0 and index < len(units) - 1:
        size /= 1024.0
        index += 1
    if index == 0:
        return "%d %s" % (int(size), units[index])
    return "%.1f %s" % (size, units[index])


def format_duration(seconds):
    # compact duration for timeline gaps, e.g. 90 -> "1m30s"
    if seconds is None:
        return "unknown"
    seconds = abs(seconds)
    if seconds < 1:
        return "0s"
    if seconds < 60:
        return "%ds" % int(seconds)
    if seconds < 3600:
        return "%dm%ds" % (int(seconds // 60), int(seconds % 60))
    if seconds < 86400:
        return "%dh%dm" % (int(seconds // 3600), int((seconds % 3600) // 60))
    return "%dd%dh" % (int(seconds // 86400), int((seconds % 86400) // 3600))
