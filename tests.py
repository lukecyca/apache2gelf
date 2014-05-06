import unittest
from apache2gelf import parse_timestamp, parse_message


class TestApacheGELF(unittest.TestCase):

    def test_access_timestamp_no_timezone(self):
        self.assertEquals(
            parse_timestamp('04/May/2014:07:53:54 +0000'),
            1399190034.0
        )

    def test_access_timestamp_timezone(self):
        self.assertEquals(
            parse_timestamp('04/May/2014:07:53:54 -0700'),
            1399215234.0
        )

    def test_error_timestamp(self):
        self.assertEquals(
            parse_timestamp('Sun May 04 07:53:36 2014'),
            1399190016.0
        )

    def test_invalid_timestamp(self):
        with self.assertRaises(ValueError):
            parse_timestamp('June 5th, Last year')

    def test_parse_access_combined(self):
        line = (
            '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" '
            '"Mozilla/4.08 [en] (Win98; I ;Nav)"'
        )

        record = parse_message(line, 'combined', {'_vhost': 'bkpr.ca:80'})

        self.assertEquals(record['timestamp'], 971211336.0)
        self.assertEquals(record['short_message'], line)

        self.assertEquals(record['_username'], 'frank')
        self.assertEquals(record['_request'], 'GET /apache_pb.gif HTTP/1.0')
        self.assertEquals(record['_referer'], 'http://www.example.com/start.html')
        self.assertEquals(record['_useragent'], 'Mozilla/4.08 [en] (Win98; I ;Nav)')
        self.assertEquals(record['_size'], '2326')
        self.assertEquals(record['_ipaddr'], '127.0.0.1')
        self.assertEquals(record['_status'], '200')
        self.assertEquals(record['_vhost'], 'bkpr.ca:80')

    def test_parse_access_vhost_combined(self):
        line = (
            'bkpr.ca:80 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" '
            '"Mozilla/4.08 [en] (Win98; I ;Nav)"'
        )

        record = parse_message(line, 'vhost_combined')

        self.assertEquals(record['timestamp'], 971211336.0)
        self.assertEquals(record['short_message'], line)

        self.assertEquals(record['_username'], 'frank')
        self.assertEquals(record['_request'], 'GET /apache_pb.gif HTTP/1.0')
        self.assertEquals(record['_referer'], 'http://www.example.com/start.html')
        self.assertEquals(record['_useragent'], 'Mozilla/4.08 [en] (Win98; I ;Nav)')
        self.assertEquals(record['_size'], '2326')
        self.assertEquals(record['_ipaddr'], '127.0.0.1')
        self.assertEquals(record['_status'], '200')
        self.assertEquals(record['_vhost'], 'bkpr.ca:80')

    def test_parse_error(self):
        line = (
            '[Sun May 04 07:47:52 2014] [warn] '
            'Init: Name-based SSL virtual hosts only work for '
            'clients with TLS server name indication support (RFC 4366)'
        )

        record = parse_message(line, 'error')

        self.assertEquals(record['timestamp'], 1399189672.0)
        self.assertEquals(record['short_message'],
                          'Init: Name-based SSL virtual hosts only work for '
                          'clients with TLS server name indication support (RFC 4366)')

        self.assertEquals(record['_level'], 'warn')

    def test_parse_error_request(self):
        line = (
            '[Sun May 04 07:53:36 2014] [error] [client 21.138.241.56] '
            'File does not exist: /var/www/lukecyca.com/favicon.ico'
        )

        record = parse_message(line, 'error')

        self.assertEquals(record['timestamp'], 1399190016.0)
        self.assertEquals(record['short_message'],
                          'File does not exist: /var/www/lukecyca.com/favicon.ico')

        self.assertEquals(record['_level'], 'error')
        self.assertEquals(record['_ipaddr'], '21.138.241.56')
