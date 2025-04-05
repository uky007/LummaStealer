import requests
from bs4 import BeautifulSoup
import re
import sys

key = 0x0f
domain_regex = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def deobf_c2_caesar(s, key):
    result = ""
    for c in s:
        if ord(c) == ord('-') or ord(c) == ord('.'):
            result += c
        elif ord(c) + key > ord('z'):
            result += chr(ord(c)  - (26 - key))
        else:
            result += chr(ord(c) + key)
    return result


def get_caesar_c2(url):
    urls = []

    response = requests.get(url)
    #print(response.text)

    bs = BeautifulSoup(response.text, "html.parser")
    actual_persona_names = bs.find_all("span", class_="actual_persona_name")
    for actual_persona_name in actual_persona_names:
        urls.append(actual_persona_name.text)

    return urls


def main():

    #url = "https://steamcommunity.com/profiles/76561199724331900"
    if len(sys.argv) < 2:
        print("[!!] Usage: {} <url>".format(sys.argv[0]))
        sys.exit(1)

    url = sys.argv[1]
    caesal_urls = get_caesar_c2(url)
    #print(caesal_urls)
    urls = []
    for caesar_url in caesal_urls:
        if domain_regex.match(caesar_url):
            urls.append(deobf_c2_caesar(caesar_url, key))
    print(urls)

if __name__ == "__main__":
    main()