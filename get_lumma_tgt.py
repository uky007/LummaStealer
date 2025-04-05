import requests
import json
import sys
import base64
import os

def lummac2(c2, endpoint):

    if endpoint[0] != "/":
        endpoint = "/" + endpoint

    endpoint = "https://" + c2 + endpoint
    if endpoint == "/api":
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        data = {"act": "life"}
    else:
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
        data = {
            "uid": "25267d0538603174d8065b30cff05f92b180b2ba14f9",
            "cid":""
        }
    
    con_type = "application/x-www-form-urlencoded"
    headers = {
        "User-Agent": ua,
        "Content-Type": con_type,
    }
    print(endpoint)
    response = requests.post(endpoint, data=data, verify=False, headers=headers)
    print(response.text)
    if response.text == "ok":
        data = {
            "act": "recive_message",
            "ver": "4.0",
            "lid": "1NCW25--589",
            "j": "default",
        }
        response = requests.post(endpoint, data=data, verify=False, headers=headers)
        print(response.text)
        conf = lummac2_decoder(response.text)
        '''
        with open("chrome.zip", 'rb') as f:
            z = f.read()
            response = requests.post(endpoint, data=z, verify=False, headers=headers)
            print(response)
        '''
        return conf
    else:
        print("[-] Unexpect response from LummaC2")
        print(response.text)
        return response.text

def lummac2_decoder(data):
    data_list = data.split('\n')
    for d in data_list:
        b64_data = base64.b64decode(d)
        target = b64_data[:32]
        key = b64_data[32:]
        
        result = ""
        for i in range(len(key)):
            result += chr(target[i % 32] ^ key[i % len(key)])
    
    return json.loads(result)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3", sys.argv[0], "<lummac2 addr>")
        exit(1)
    
    c2 = sys.argv[1]
    
    try:
        endpoint = sys.argv[2]
    except IndexError:
        endpoint = "/api"

    res = lummac2(c2, endpoint)
    print(res)
    tgt_file = "{}_{}".format(c2, "config.json")
    tgt_path = tgt_path = os.path.join(os.environ['HOME'], "lummac2", tgt_file)
    with open(tgt_path, "w") as f:
        f.write(json.dumps(res))
        print("Wrote LummaC2 config:", tgt_path)

if __name__ == "__main__":
    main()