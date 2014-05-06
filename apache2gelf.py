#!/usr/bin/env python
import sys
import re
import argparse
import socket
import zlib
import json
from datetime import timedelta, datetime, tzinfo


#: Maximum chunk size of UDP packet
MAX_CHUNK_SIZE = 8154


FORMATS = {

    'combined': re.compile(
        '^(?P<_ipaddr>\S+) \S+ (?P<_username>\S+) \[(?P<timestamp>[^\]]+)\] '
        '"(?P<_request>[^"]*)" (?P<_status>\S+) (?P<_size>\S+) '
        '"(?P<_referer>[^"]*)" "(?P<_useragent>[^"]*)"$'
    ),

    'vhost_combined': re.compile(
        '^(?P<_vhost>\S+) (?P<_ipaddr>\S+) \S+ (?P<_username>\S+) \[(?P<timestamp>[^\]]+)\] '
        '"(?P<_request>[^"]*)" (?P<_status>\S+) (?P<_size>\S+) '
        '"(?P<_referer>[^"]*)" "(?P<_useragent>[^"]*)"$'
    ),

    'error': re.compile(
        '^\[(?P<timestamp>[^\]]+)\] \[(?P<_level>[^\]]*)\] '
        '(\[client (?P<_ipaddr>[^\]]*)\] )?(?P<short_message>.*)$'
    ),

}


class FixedOffsetTimeZone(tzinfo):
    """Fixed offset in minutes east from UTC."""

    def __init__(self, offset, name=None):
        self.__offset = timedelta(minutes=offset)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return timedelta(0)


def parse_timestamp(s):
    """Parses a timestamp string in the form 04/May/2014:18:56:11 +0000
    and returns a UTC unix timestamp"""
    try:
        naive_dt = datetime.strptime(s, '%a %b %d %H:%M:%S %Y')  # Apache error format
        dt = naive_dt.replace(tzinfo=FixedOffsetTimeZone(0))

    except ValueError:
        naive_date_str, _, offset_str = s.rpartition(' ')
        naive_dt = datetime.strptime(naive_date_str, '%d/%b/%Y:%H:%M:%S')  # Apache access format
        offset = int(offset_str[:3]) * 60 + int(offset_str[-2:])
        dt = naive_dt.replace(tzinfo=FixedOffsetTimeZone(offset))

    return (dt - datetime(1970, 1, 1, tzinfo=FixedOffsetTimeZone(0, 'UTC'))).total_seconds()


def parse_message(s, format_, baserecord={}):
    record = dict(baserecord)

    matches = FORMATS[format_].search(s)
    if matches:
        for k, v in matches.groupdict().items():
            try:
                record[k] = int(v)
            except (ValueError, TypeError):
                pass

            try:
                record[k] = float(v)
            except (ValueError, TypeError):
                pass

            record[k] = v

    # Convert the timestamp
    if record.get('timestamp'):
        record['timestamp'] = parse_timestamp(record['timestamp'])

    # Include the raw message if not already set
    if not record.get('short_message'):
        record['short_message'] = s.strip()

    return record


def main():
    parser = argparse.ArgumentParser(
        description='Reads apache access log on stdin and sends '
                    'messages to graylog2 server via GELF',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--hostname',
                        help='local host name (default: `hostname`)')
    parser.add_argument('--server',
                        default='localhost',
                        help='graylog2 server hostname (default: localhost)')
    parser.add_argument('--port',
                        metavar='N',
                        type=int,
                        default=12201,
                        help='graylog2 server port (default: 12201)')
    parser.add_argument('--vhost',
                        help='Add additional "vhost" field to all log records. '
                             'This can be used to differentiate between virtual hosts.')
    parser.add_argument('--format',
                        dest='format_',
                        metavar='FORMAT',
                        help='One of: ' + ', '.join(FORMATS))
    parser.add_argument('--tcp',
                        action='store_true',
                        help='Use TCP instead of UDP')
    args = parser.parse_args()

    if args.vhost and args.format_ == 'vhost_combined':
        raise ValueError('Must not specify vhost argument if using vhost_combined')

    baserecord = {
        'version': '1.1',
        'host': args.hostname or socket.gethostname(),
    }
    if args.vhost:
        baserecord['_vhost'] = args.vhost

    if args.tcp:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((args.server, args.port))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for line in iter(sys.stdin.readline, b''):
        line = line.strip()
        record = parse_message(line, args.format_, baserecord)
        print(line)

        if args.tcp:
            s.send(json.dumps(record) + '\0')

        else:
            zmessage = zlib.compress(json.dumps(record))
            s.sendto(zmessage, (args.server, args.port))

    s.close()

if __name__ == "__main__":
    main()
