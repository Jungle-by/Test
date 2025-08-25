import random
import re
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
import requests

# see https://github.com/douniwan5788/zte_modem_tools/issues/20#issuecomment-2849666205
from rss import create_payload_array, verify_do_check_client, parse_mac

ROOT = "http://192.168.1.1"
USERNAME = "user"
PASSWORD = "user"
LOCAL_MAC = parse_mac('00:01:02:03:04:05') # your machine's MAC address

# share state between requests
s = requests.Session()
rand = random.Random()

KEY_POOL = [
    0x9c, 0x33, 0x75, 0xd1, 0x1c, 0x42, 0x45, 0x37, 0x18, 0x48,
    0x91, 0x73, 0x17, 0x45, 0x79, 0x44, 0x43, 0xd7, 0xd5, 0x73,
    0x33, 0x54, 0x76, 0xd2, 0xc5, 0xf1, 0x2c, 0x4f, 0x7a, 0xba,
    0x61, 0xd9, 0x5c, 0x69, 0xdf, 0x8c, 0xd2, 0x1c, 0xde, 0x3b,
    0x35, 0x2d, 0x2f, 0xe1, 0xde, 0x4c, 0x77, 0xf5, 0x1a, 0x65,
    0xd1, 0xfe, 0x18, 0x43, 0x8e, 0xa7, 0x42, 0x08, 0x04, 0x78,
    0xd5, 0xe4, 0xf3, 0x34, 0xa4, 0xd3, 0xf2, 0x36, 0x47, 0x6d,
    0x86, 0x9d, 0x42, 0x65, 0x13, 0x42, 0xdc, 0x42, 0x99, 0x48,
    0xdc, 0x67, 0x9f, 0x9e, 0xdc, 0x46, 0x37, 0x5f, 0x84, 0x9f,
    0x6f, 0x76, 0xce, 0x79, 0x4f, 0x49,
]

def pad(data_to_pad, block_size):
    padding_len = block_size-len(data_to_pad) % block_size
    return data_to_pad+b'\x00'*padding_len

def unpad(padded_data, block_size):
    return padded_data[:-block_size] + padded_data[-block_size:].rstrip(b'\x00')

def main():
    print("======= RESET =======")
    url = "/webFac"
    payload = 'SendSq.gch'
    print(f'--> POST {url} "{payload}"')

    res = s.post(ROOT + url, data=payload)
    if res.status_code != 400:
        raise Exception("expected error 400")


    print("======= STEP 1 =======")

    url = "/webFac"
    payload = 'RequestFactoryMode.gch'

    print(f'--> POST {url} "{payload}"')

    try:
        s.post(ROOT + url, data=payload)
    except requests.exceptions.ConnectionError:
        # expected
        pass
    else:
        raise Exception("expected ConnectionError")


    print("======= STEP 2 =======")

    # generate a random number, range 0-59
    #client_rand = rand.randint(0, 59)
    client_rand = 0 # chosen by fair D60 roll. (called Sq in /bin/httpd)

    url = "/webFac"
    payload = f'SendSq.gch?rand={client_rand}\r\n'

    print(f'--> POST "{payload.strip()}"')

    res = s.post(ROOT + url, data=payload)
    print(f'<-- {res.status_code} {len(res.content)} bytes ({res.text})')

    # match response
    match = re.match(r"re_rand=([^&]+)&([^&]+)&([^&]+)", res.text)
    if match is None:
        raise Exception(f"expected re_rand, got {res.text}")

    # split and extract components
    server_rand, rand_seed_trunc, server_mac_bytes  = match.groups()
    server_rand = int(server_rand)
    rand_seed_trunc = int(rand_seed_trunc)

    server_mac = server_mac_bytes.encode('latin-1')
    print(f"{server_rand=}")
    print(f"{rand_seed_trunc=}")
    print(f"server_mac={server_mac.hex()}")

    print("======= STEP 3 =======")

    # mix with FNV prime & mask
    client_rand_mix = (0x1000193 * client_rand)
    client_rand_mask = client_rand_mix & 0x8000003f
    print(f"{client_rand_mix=}")
    print(f"{client_rand_mask=}")

    client_xor_server = client_rand_mask ^ server_rand
    client_xor_server_mod = client_xor_server % 60
    print(f"{client_xor_server=}")
    print(f"{client_xor_server_mod=}")

    # g_iRsaIndex = indexCal(rand_seed_trunc, client_xor_server_mod, server_mac_bytes);
    index = client_xor_server_mod
    print(f"{index=}")

    aes_key = map(lambda x: (x ^ 0xA5) & 0xFF, KEY_POOL[index:index + 24])
    aes_key = bytes(aes_key)
    print(f"aes_key={aes_key.hex()}")

    aes = AES.new(aes_key, AES.MODE_ECB)

    print(f"local_mac={LOCAL_MAC.hex()}")

    payload_arr = create_payload_array(server_mac, LOCAL_MAC, index)
    if not verify_do_check_client(payload_arr, LOCAL_MAC, index, server_mac):
        print("we are sad :(")

    payload = f"SendInfo.gch?info={len(payload_arr)}|{b''.join(map(lambda x: x.to_bytes(4, 'little'), payload_arr)).decode('utf-8')}"

    url = "/webFacEntry"
    print(f'--> POST {url} "{payload}"')

    res = s.post(
        ROOT + url,
        data=aes.encrypt(
            pad(payload.encode(), 16)
        )
    )
    print(f'<-- {res.status_code} {len(res.content)} bytes')
    if res.status_code != 200:
        raise Exception(f"expected 200. got {res.status_code}")

    print("======= STEP 4 =======")

    url = "/webFacEntry"
    payload = f'CheckLoginAuth.gch?version50&user={USERNAME}&pass={PASSWORD}'
    print(f'--> POST {url} "{payload}"')

    res = s.post(
        ROOT + url,
        data=aes.encrypt(
            pad(payload.encode(), 16)
        )
    )

    print(f'<-- {res.status_code} {len(res.content)} bytes (encrypted)')
    if res.status_code != 200:
        raise Exception(f"expected 200. got {res.status_code}")

    res_url = unpad(aes.decrypt(res.content), 16)
    print(f"{res_url=}")

    if res_url != b'FactoryMode.gch\x00':
        raise Exception(f"expected result to match 'FactoryMode.gch'")

    print("======= STEP 5 =======")

    url = "/webFacEntry"
    mode = 2
    payload = f'FactoryMode.gch?mode={mode}&user=notused'

    print(f'--> POST {url} "{payload}"')

    res = s.post(
        ROOT + url,
        data=aes.encrypt(
            pad(payload.encode(), 16)
        )
    )

    print(f'<-- {res.status_code} {len(res.content)} bytes')

    decrypted = aes.decrypt(res.content).rstrip(b'\x00').decode()
    print(f"{decrypted=}")

    parsed = parse_qs(urlparse(decrypted).query)
    username = parsed['user'][0]
    password = parsed['pass'][0]

    print(f"{username=}")
    print(f"{password=}")

main()

