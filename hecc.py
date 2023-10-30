import requests
import urllib.parse
import json
import base64
import uuid
import time
import os
import binascii

def get_proxies():
    return None



counter_server = "Nie powiem"

def incr_counter(name, time):
    requests.post(f"{counter_server}/{name}/{os.environ['COMPUTERNAME']}", json={
        "time": time
    })



def gen_task():
    clientUuid = str(uuid.uuid4())
    verbose = False
    session = requests.Session()
    session.proxies = get_proxies()
    headers = {
    'connection': 'keep-alive',
    'x-tt-store-region-user': 'pl',
    'passport-sdk-version': '30856',
    'sdk-version': '2',
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'user-agent': 'com.nvsgames.snap/176 (Linux; U; Android 7.1.2; pl_PL; SM-G988N; Build/QP1A.190711.020; Cronet/TTNetVersion:d5a7acd8 2022-07-15 QuicVersion:b314d107 2021-11-24)',
}
    def redeem_nitro():
        params = {
            'is_new_user': '0',
            '_signature': '_02B4Z6wo0090155xljwAAIDCvdC4kHzeP0-ecZKAAIK08d',
        }
        json_data = {
            'did': 'undefined',
            'channel': '1',
            'channel_app_id': '262304',
            'login_type': 'passport',
            'from_source': 'UNKNOWN',
            'launch_way': '',
            'launch_from': 'unknown',
            'language': 'en',
            'url': 'https://www.marvelsnap.com/discordnitrocollab?is_new_user=0',
            'page_id': 'https://www.marvelsnap.com/discordnitrocollab',
            'share_url': '',
            'session_id': 'd3dd6F0GiFJ24aB41Bh7hhh40i0DJ7cD',
            'event_id': 'FCHj6IfAaFfCk9ICchcH0feGchbBI8hG',
            'platform': 'pc',
            'activity_id': '30111445',
            'is_new_user': '0',
            'process_id': '7283450291146676997',
            'ui_process_id': 'undefined',
            'shark_params': {
                'header': {
                    'is_new_user': '0',
                    'host_app_id': '262304',
                    'app_id': '262304',
                    'app_name': '',
                    'app_version': '0.0.0',
                    'gsdk_version': '0.0.0',
                    'app_language': 'pl-PL',
                    'os_name': 'android',
                    'os_version': '0.0.0',
                    'network_type': '4g',
                    'time': 1697657595275,
                    'event': '',
                    'user_is_auth': False,
                },
                'webheader': {
                    'app_id': '262304',
                    'activity_type': -1,
                    'activity_id': '30111445',
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                    'referer': 'https://accounts.google.pl/',
                    'cookie_enabled': True,
                    'screen_width': 2560,
                    'screen_height': 1440,
                    'browser_type': 5,
                    'browser_language': 'pl-PL',
                    'browser_platform': 'Win32',
                    'browser_name': 'Mozilla',
                    'browser_version': '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                    'browser_online': True,
                    'timezone_name': 'Europe/Warsaw',
                    'time': 1697657595275,
                },
                'params': {
                    'inf_from': -1,
                    'aid': '262304',
                    'app_name': '',
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                },
            },
        }
        response = session.post(
            'https://www.marvelsnap.com/act/262304/process/exec/v2',
            params=params,
            headers={
                'connection': 'keep-alive',
                'x-request-timestamp': '1697657595',
                'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
                'content-type': 'application/json',
                'sec-ch-ua-mobile': '?0',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
                'sec-ch-ua-platform': '"Windows"',
                'accept': '*/*',
                'origin': 'https://www.marvelsnap.com',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': 'https://www.marvelsnap.com/discordnitrocollab?is_new_user=0',
                'accept-language': 'pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7',
            },
            json=json_data,
            cookies=session.cookies.get_dict(".bytegsdk.com")
        )
        link = response.json()['data']['link']['value']['link']
        open('promos.txt','a').write(link+ '\n')
    jwt_body1 = {"alg":"RS256","typ":"JWT"}
    jwt_body1 = base64.b64encode(json.dumps(jwt_body1).encode()).decode()
    sub = "discordggzsl" + str(int(time.time() * 1000))
    jwt_body2 = {"sub": sub } # tu dajezs jakakolwiek losowa wartosc
    jwt_body2 = base64.b64encode(json.dumps(jwt_body2).encode()).decode()
    jwt_body3 = "Boykisser"
    data = {
        'platform_app_id': '1898',
        'platform': 'obywatelska',
        'account_sdk_source': 'app',
        'access_token_secret': '.'.join([jwt_body1, jwt_body2, jwt_body3]),
        'expires_in': '0',
        'multi_login': '1'
    }
    custom = urllib.parse.quote(json.dumps({
                'channel_op': 'bsdkintl', 
                'ban_odin': 1, 
                'store_region_user': 'pl', 
                'app_version_minor': '20.23.0', 
                'store_region_device': '', 
                'gm_patch_version': '', 
                'launch_type': 2,
                'game_id': 262304, 
                'environment': 'online',
                'user_is_login': 1, 
                'new_country': 'pl', 
                'is_emulator': '1', 
                'country': 'pl', 
                'encrypt_ticket_id': '', 
                'g_download_source': '', 
                'new_city': 'stary poznan', 
                'new_province': 'greater poland', 
                'emulator_type': 'spierdalaj xd', 
                'adjust_id': '', 
                'version_code': '176', 
                'device_platform': 'android', 
                'login_way': 'guest',}))
    response = session.post(
        'https://gsdk-va.bytegsdk.com/passport/auth/login/',
        headers=headers,
        data=data,
        params={
            "passport-sdk-version": "30856",
            "ac": "wifi",
            "channel": "GooglePlay",
            "aid": "262304",
            "app_name": "snap_nvs",
            "version_code": "176",
            "version_name": "20.23.0",
            "device_platform": "android",
            "os": "android",
            "ssmix": "a",
            'cdid': clientUuid,
            "device_type": "Nigga",
            "device_brand": "samsung",
            "language": "en",
            "os_api": "25",
            "os_version": "7.1.2",
            "manifest_version_code": "176",
            "resolution": "900*1600",
            "dpi": "240",
            "update_version_code": "176",
            "carrier_region": "PL",
            "tz_offset": "3600",
            "sdk_app_id": "1782",
            "sdk_language": "en_US",
            "login_way": "guest",
            "sys_region": "PL",
            "g_download_source": "",
            "shark_extra": "%7B%22gsdk_version_code%22%3A%223.20.0.0%22%7D",
            "login_type": "auto",
            "channel_op": "bsdkintl",
            "sdk_version": "3.20.0.0",
            "device_model": "Nigga",
            "app_package": "com.nvsgames.snap",
            "custom": custom,
            "adid": "",
            "game_id": "262304",
            "mcc_mnc": "26003",
            "tz_name": "Europe%2FWarsaw"
        }
    )
    if verbose:
        print("--- login resp")
        print(response.text)
    bytedance_headers = {
        'connection': 'keep-alive',
        'passport-sdk-version': '30856',
        'x-tt-token': response.headers['x-tt-token'],
        'x-gorgon': '83009f9d00009f01f62b770d5eae39dc74f25eaebbe077459123', # https://github.com/lumaaaaaa/ttDownloader/blob/master/gorgon.go
        'x-khronos': '1697698561', # https://github.com/lumaaaaaa/ttDownloader/blob/master/gorgon.go
        'x-ss-stub': '92AB256E882BE46326D7DDECBDCB72DA', # some hash, time to frida!
        'x-tt-trace-id': '00-46b83e0c010466dff0280b4f85feffff-46b83e0c010466df-01',
        'sdk-version': '2',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'user-agent': 'com.nvsgames.snap/175 (Linux; U; Android 8.1.2; pl_PL; SM-G988N; Build/QP1A.190711.020;)',
    }
    bytedance_params = {   '_rticket': '1697699838976',
        'ac': 'wifi',
        'aid': '262304',
        'app_name': 'snap_nvs',
        'app_package': 'com.nvsgames.snap',
        'appsflyer_id': '1697698560592-5598831164389349350',
        'carrier_region': 'PL',
        'cdid': clientUuid,
        'channel': 'GooglePlay',
        'channel_op': 'bsdkintl',
        'client_uuid': clientUuid,
        'custom': custom,
        'device_brand': 'samsung',
        'device_model': 'SM-G988N',
        'device_platform': 'android',
        'device_type': 'SM-G988N',
        'dpi': '240',
        'event_seq': clientUuid,
        'game_id': '262304',
        'language': 'en',
        'login_type': 'home',
        'login_way': 'google',
        'manifest_version_code': '176',
        'mcc_mnc': '26003',
        'openudid': 'baa7d22d386e76c9',
        'os': 'android',
        'os_api': '25',
        'os_version': '7.1.2',
        'resolution': '1600*900',
        'sdk_app_id': '1782',
        'sdk_language': 'en_US',
        'sdk_version': '3.20.0.0',
        'shark_extra': '{"gsdk_version_code":"3.20.0.0"}',
        'ssmix': 'a',
        'sys_region': 'PL',
        'tz_name': 'Europe/Warsaw',
        'tz_offset': '3600',
        'update_version_code': '176',
        'version_code': '176',
        'version_name': '20.23.0'}
    if False:
        bytedance_device_register = session.post(
            'https://log-va.bytegsdk.com/service/2/device_register/',
            params={   
            '_rticket': str(int(time.time() * 1000)),
            'ac': 'wifi',
            'aid': '262304',
            'app_name': 'snap_nvs',
            'app_package': 'com.nvsgames.snap',
            'carrier_region': 'PL',
            'channel': 'GooglePlay',
            'channel_op': 'bsdkintl',
            'device_brand': 'samsung',
            'device_model': 'SM-G988N',
            'device_platform': 'android',
            'device_type': 'SM-G988N',
            'dpi': '240',
            'game_id': '262304',
            'language': 'pl',
            'login_type': 'unknown',
            'login_way': 'unknown',
            'manifest_version_code': '176',
            'mcc_mnc': '26003',
            'openudid': 'baa7d22d386e76c9',
            'os': 'android',
            'os_api': '25',
            'os_version': '7.1.2',
            'resolution': '1600*900',
            'sdk_app_id': '1782',
            'sdk_language': 'pl_PL',
            'sdk_version': '3.20.0.0',
            'shark_extra': '{"gsdk_version_code":"3.20.0.0"}',
            'ssmix': 'a',
            'sys_region': 'PL',
            'tt_data': 'a',
            'tz_name': 'Europe/Warsaw',
            'tz_offset': '3600',
            'update_version_code': '176',
            'version_code': '176',
            'version_name': '20.23.0',
            **bytedance_params},
            headers=bytedance_headers,
        )
        print(bytedance_device_register.text)
        bytedance_device_register = bytedance_device_register.json()
        print("-- device register: ")
        print(bytedance_device_register)
        bytedance_params['iid'] = bytedance_device_register['install_id']
        bytedance_params['device_id'] = bytedance_device_register['device_id']
    else:
        bytedance_params['iid'] = '7291364572236105477'
        bytedance_params['device_id'] = '7291363459307898374'
    bytedance_token = session.post(
        'https://gsdk-va.bytegsdk.com/sdk/account/login',
        params=bytedance_params,
        headers=bytedance_headers,
        data={
            'user_type': '5',
            'ui_flag': '0',
            'login_id': clientUuid,
        },
    )
    if verbose:
        print("--- bytedance token login resp")
        print(bytedance_token.text)
    bytedance_uid = bytedance_token.json()["data"]["user_id"]
    bytedance_token = bytedance_token.json()["data"]["token"]
    ### SDK AUTHLLOGIN STEP 2
    response = requests.post(
        'https://gsdk-va.bytegsdk.com/gsdk/account/login',
        proxies=get_proxies(),
        headers={
            'connection': 'keep-alive',
            'passport-sdk-version': '30856',
            'sdk-version': '2',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'user-agent': 'com.nvsgames.snap/176 (Linux; U; Android 7.1.2; pl_PL; SM-G988N; Build/QP1A.190711.020; Cronet/TTNetVersion:d5a7acd8 2022-07-15 QuicVersion:b314d107 2021-11-24)',
        },
        params=bytedance_params,
        data={
            'data': '{"user_id":"' + str(bytedance_uid) + '","token":"' + bytedance_token + '"}',
            'channel_id': 'bsdkintl',
            'login_id': clientUuid,
            'iid': bytedance_params['iid'],
            'ui_flag': '0',
            'device_id': bytedance_params['device_id'],
            'login_type': 'home',
            'adjust_id': '',
        }
    )
    if verbose:
        print("--- gsdk accuont login")
        print(response.text)
    bytedance_response = response.json()['data']
    bytedance_token = bytedance_response['access_token']
    clientsession = base64.b64encode(json.dumps(
        {"Id": clientUuid, "Bytedance":{"SdkOpenId": bytedance_response["sdk_open_id"],"DeviceId":bytedance_params['device_id'],"AppId":262304,"Country":"Poland","CountryAscii":"The Republic of Poland","CountryCode":"PL"},"Device":{"Id":binascii.b2a_hex(os.urandom(15)).decode(),"Model":"samsung SM-G988N","Platform":"Android","Language":"English"}}
    ).encode()).decode()
    unity_headers = {
        'user-agent': 'UnityPlayer/2021.3.19f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)',
        'accept': '*/*',
        'content-type': 'application/json',
        'clientsession': clientsession,
        'x-unity-version': '2021.3.19f1',
    }
    # uncomment if you want register 
    register_req = requests.post(
        'https://global-cf.nvprod.snapgametech.com/v20.23/1/account/registerAccount',
        headers=unity_headers,
        proxies=get_proxies(),
        json={
            'LocationLanguage': "en-IE",
            'PrivacySettings': {
                'PrivacyPolicyVersionAccepted': 4,
                'TermsOfServiceVersionAccepted': 2
            },
            'RegistrationLocation': 'PL',
        },
    )
    register_req_token = register_req.json()["AuthorizationToken"]
    unity_headers['Authorizationtoken'] = register_req_token
    migration = requests.post(
        'https://eu-central-1-cf.nvprod.snapgametech.com/v20.23/1/progression/schema/executeMigration',
        headers=unity_headers,
        json={
        },proxies=get_proxies()
    ) # this thing creates profile in database, required as fuck!!!
    def fire_and_forget(*args, **kwargs):
        try:
            requests.post(*args,**kwargs)
        except: 
            pass
    bytedance_init = fire_and_forget(
        'https://eu-central-1-cf.nvprod.snapgametech.com/v20.23/1/progression/bytedance/init',
        headers=unity_headers,
        json={"BytedanceAccessToken": bytedance_token},proxies=get_proxies()
    )
    for init_name in ['shop', 'mission', 'inbox', 'battlePass', 'conquest', 'reward', 'profile']:
        init = fire_and_forget(
            'https://eu-central-1-cf.nvprod.snapgametech.com/v20.23/1/progression/' + init_name + '/init',
            headers=unity_headers,
            json={},
        )
        if verbose:
            print(init_name + ":")
            print(init.text)
    deck_init = fire_and_forget(
        'https://eu-central-1-cf.nvprod.snapgametech.com/v20.23/1/progression/collection/init',
        headers=unity_headers,
        json={"StarterDeckName": "Deck 1"},proxies=get_proxies()
    )
    response = fire_and_forget(
        'https://eu-central-1-cf.nvprod.snapgametech.com/v20.23/1/progression/battlePass/acknowledgePromo',
        headers=unity_headers,
        json={},proxies=get_proxies()
    )
    deck_data = requests.post(
        'https://eu-central-1-cf.nvprod.snapgametech.com/v20.23/1/progression/collection/getState',
        headers=unity_headers,
        json={},proxies=get_proxies()
    ).json()['Collection']['Decks'][0]

    for i in range(10):
        time_elapsed = time.time()

        resp = session.get('http://127.0.0.1:8080/do', json={
            "clientsession": clientsession,
            "authorizationtoken": unity_headers['Authorizationtoken'],
            "deck_data": deck_data
        })

        time_elapsed = time.time() - time_elapsed

        if resp.status_code != 200:          
            raise Exception("game play failed :(")
    redeem_nitro()