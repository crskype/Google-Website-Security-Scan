import requests
import threadpool
import json
import time


class GoogleWebsiteSecurity(object):
    session = requests.session()
    session.headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN,zh;q=0.9',
        'referer': 'https://transparencyreport.google.com/safe-browsing/search',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                      ' Chrome/66.0.3359.181 Safari/537.36'
    }
    _ufa = {
        1: '未发现不安全的内容',
        3: '此网站的部分网页不安全',
        2: '此网站不安全',
        5: '此网站上托管了用户不常下载的文件',
        4: '检查一个具体的网址',
        0: '没有数据可显示',
        6: '没有数据可显示',
    }
    _ufa_unknown = '未知'
    _url = 'https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status'
    _params = {'site': None}

    def __init__(self, ignore_cert_errors=False):
        self.session.verify = not ignore_cert_errors  # debug

    def query(self, site):
        self._params.update({'site': site})
        res = self.session.get(self._url, params=self._params)
        if not res.text.startswith(")]}'\n"):
            res.close()
            return False, {}
        data = json.loads(res.text[5:])[0]
        res.close()

        checkid = data[1]
        timestamps = data[7] / 1000  # 13-bit to 10-bit
        timeformat = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamps))
        return True, {
            'text': self._ufa.get(checkid, self._ufa_unknown),
            'time': timeformat
        }


class Controller(object):
    GWS = GoogleWebsiteSecurity()

    def __init__(self):
        data = self.GWS.query('baidu.com')
        print(data)


if __name__ == '__main__':
    Controller()
