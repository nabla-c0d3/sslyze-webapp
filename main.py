import logging
from typing import List

import falcon
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sslyze import ServerNetworkLocationViaDirectConnection, CipherSuitesScanResult, ServerConnectivityTester, Scanner, \
    ServerScanRequest, ScanCommand
from sslyze.errors import ConnectionToServerFailed

jinja_env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger("sslyze-webapp")


CIPHER_SUITES_SCAN_CMDS = {
        #ScanCommand.SSL_2_0_CIPHER_SUITES,
        #ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        #ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        #ScanCommand.TLS_1_3_CIPHER_SUITES,
    }


def run_cipher_suites_scan(hostname: str, port: int) -> List[CipherSuitesScanResult]:
    # Ensure we can connect to the sever
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, port)
    server_info = ServerConnectivityTester().perform(server_location)

    # Scan for all cipher suites
    _logger.info(f"Running scan for {hostname}:{port}")
    server_scan_req = ServerScanRequest(server_info=server_info, scan_commands=CIPHER_SUITES_SCAN_CMDS)
    scanner = Scanner()
    scanner.queue_scan(server_scan_req)

    # Then retrieve the results
    scan_results = []
    for server_scan_result in scanner.get_results():
        for cipher_suite_scan_cmd in CIPHER_SUITES_SCAN_CMDS:
            scan_results.append(server_scan_result.scan_commands_results[cipher_suite_scan_cmd])

    _logger.info(f"Scan completed; received {len(scan_results)} results")
    return scan_results


class IndexPage:

    def on_get(self, request: falcon.Request, response: falcon.Response):

        index_template = jinja_env.get_template("index.html")
        response.body = index_template.render()
        response.content_type = falcon.MEDIA_HTML


class ScanResultPage:

    def on_post(self, request: falcon.Request, response: falcon.Response):
        hostname = request.get_param("hostname")
        port = request.get_param_as_int("port")

        try:
            cipher_suites_scan_results = run_cipher_suites_scan(hostname, port)
        except ConnectionToServerFailed as e:
            result_template = jinja_env.get_template("scan_error.html")
            response.body = result_template.render(
                hostname=hostname, port=port, error_message=e.error_message,
            )
            response.content_type = falcon.MEDIA_HTML
            return

        result_template = jinja_env.get_template("scan_result.html")
        response.body = result_template.render(
            hostname=hostname, port=port, cipher_suites_scan_results=cipher_suites_scan_results,
        )
        response.content_type = falcon.MEDIA_HTML


app = application = falcon.API()
app.req_options.auto_parse_form_urlencoded=True
app.add_route('/', IndexPage())
app.add_route('/scan_result', ScanResultPage())
