def request_passed(case, kind, exit_code, http_status, campus_seen, wifi_online, proxy_seen=False):
    if case == 'missing':
        return exit_code != 0
    if kind == 'proxy':
        return exit_code == 0 and http_status == '204' and proxy_seen
    if kind == 'direct':
        if not campus_seen:
            return False
        return (exit_code == 0 and http_status == '200') if wifi_online else exit_code != 0
    return False
