import json, re
from urllib.parse import urlparse, parse_qs
import parsel
import requests
import time
import base64
import ddddocr
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class CnkiCaptcha(object):
    def __init__(self, captcha_url, session=None):
        self.captcha_url = captcha_url
        self.html_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\""
        }
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": "https://kns.cnki.net",
            "Pragma": "no-cache",
            "Referer": captcha_url,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "uniplatform": "NZKPT"
        }
        self.query_params = {key: ''.join(value) for key, value in parse_qs(urlparse(captcha_url).query).items()}
        self.session = requests.Session() if session is None else session

    def get(self):
        data = {
            'captchaType': self.query_params['captchaType'],
            'clientUid': 'b08b380bc044fd8b4736abf8d1642b7f',
            'ident': self.query_params['ident'],
            'captchaId': self.query_params['captchaId'],
            'ts': int(time.time() * 1000),
        }
        data = json.dumps(data, separators=(',', ':'))
        response = self.session.post("https://kns.cnki.net/verify-api/get", headers=self.headers,
                                     data=data)
        response = response.json()
        res = response['data']
        jigsawImageBase64 = res['jigsawImageBase64']
        originalImageBase64 = res['originalImageBase64']
        gap_pic = base64.b64decode(jigsawImageBase64)
        bg_pic = base64.b64decode(originalImageBase64)
        with open('gap.jpg', 'wb') as f:
            f.write(gap_pic)
        with open('bg.jpg', 'wb') as f:
            f.write(bg_pic)
        det = ddddocr.DdddOcr(det=False, ocr=True, show_ad=False)
        rest = det.slide_match(gap_pic, bg_pic, simple_target=True)
        value = rest['target'][0]
        # print(rest)
        # print('识别到距离', value)
        meta = {
            "secretKey": res['secretKey'],
            "token": res['token'],
            "slide": value
        }
        return meta

    @staticmethod
    def aesEncrypt(plaintext, aes_key):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(aes_key, str):
            aes_key = aes_key.encode('utf-8')
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode('utf-8')

    def check(self, token, point_json):
        json_data = {
            'captchaType': 'blockPuzzle',
            'pointJson': point_json,
            'token': token,
            'ident': 'bc397c',
            'returnUrl': self.query_params['returnUrl']
        }
        response = self.session.post("https://kns.cnki.net/verify-api/web/check", headers=self.headers,
                                     json=json_data)
        print(response.text)
        return response.json()

    def verify(self):
        meta = self.get()
        take_slide = json.dumps({"x": int(meta['slide']), "y": 5}, separators=(',', ':'))
        res1 = self.check(token=meta["token"], point_json=self.aesEncrypt(take_slide, aes_key=meta['secretKey']))
        if res1['message'] == '验证失败':
            return self.verify()
        returnUrl = res1['data']['returnUrl'] + f'&captchaId={self.query_params["captchaId"]}'
        print('第一个滑块返回的链接>>', returnUrl)
        self.html_headers['Referer'] = self.captcha_url
        return_response = self.session.get(returnUrl, headers=self.html_headers)
        print('进入第二个滑块中...')
        ecp_client_ids = re.findall(r'Ecp_ClientId=(.*?);', return_response.headers['set-cookie'])
        print(ecp_client_ids)
        return_resp = parsel.Selector(text=return_response.text)
        newlink = 'https://kns.cnki.net/kcms2/newLink?v=' + return_resp.xpath('//input[@id="v-value"]/@value').get()
        self.headers['Referer'] = returnUrl
        new_res = self.session.get(newlink, headers=headers)
        print('更新后的链接>>', new_res.text)
        return new_res.text


if __name__ == '__main__':
    session = requests.Session()
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\""
    }
    response = session.get(
        'https://kns.cnki.net/kcms2/article/abstract?v=K-Um1AVqjsI93xo4MMeoBftbYcD5zllyej6Ty4463vP-lLgPTE0rK0Lhsc3Jk33jgscJuwOwSPk8PwBPDsl9-_NWU6JqMbKzT3fqrxBdPDEEYKmuN12SJHaLgxh2kx6cB2RotQmdX4B1CW4nQ21VPKp3kvQVxe05&uniplatform=NZKPT',
        headers=headers)

    print(response.text)
    print(response.url)
    captcha_url = response.url
    # exit()
    # captcha_url = 'https://kns.cnki.net/verify/home?captchaType=blockPuzzle&ident=bc397c&captchaId=a1605a56-cc15-47cf-8efb-05244e006198&returnUrl=iECBDnhr716Qd6pbb7El10nguP5Sbm9UQxpzsYxSAM-JuReIJajXtAcIFcZlGDNKlEnlwKyQyR1jBUJZZIeMvWZAM4kHtiBdg_QKWa6xp9t_DWHKH1oOfZIbKeJX5Xn88XB3iYic9n2vq-9RuODcPCMaPD9tJ_5SrxGY61c6VtYmp3kLdvg7rGtFFfYZpUAndbcCL54DrdgrDn3s_qUI5qNBbcaps47unbB4SzoUrZG6i2HToHk5BNAFMeQJ8GoLR6szP-rDvvGWqq7HqgAoFv7ArXDc-q6stJlRMkytg21Qy8s60_Tqk3bPI2FGb1L50tkm_SeRzvDz66eQvmk5T-jYEgCZOPMa'
    cc = CnkiCaptcha(captcha_url=captcha_url)
    cc.verify()
