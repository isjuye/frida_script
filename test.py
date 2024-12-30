
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import sys
import json

def encrypt_aes_cbc(json_str, key_base64, iv_base64):
   try:
       # Base64 디코딩하여 키와 IV 바이트로 변환
       key = base64.b64decode(key_base64)
       iv = base64.b64decode(iv_base64)

       # 입력받은 문자열을 UTF-8 바이트로 변환
       plaintext_bytes = json_str.encode('utf-8')

       # PKCS5Padding 적용
       padded = pad(plaintext_bytes, AES.block_size)

       # AES-CBC 암호화
       cipher = AES.new(key, AES.MODE_CBC, iv)
       ciphertext = cipher.encrypt(padded)

       # Base64로 인코딩하여 반환
       return base64.b64encode(ciphertext).decode('utf-8')

   except Exception as e:
       print(f"Error: {str(e)}")
       return None

def main():
   if len(sys.argv) != 4:
       print("Usage: python3 script.py <json_string> <key_base64> <iv_base64>")
       print("Example:")
       print('python3 script.py \'{"channel_code":"CREDIT","country":"KR"}\' "key_in_base64" "iv_in_base64"')
       sys.exit(1)

   json_str = sys.argv[1]
   key_base64 = sys.argv[2]
   iv_base64 = sys.argv[3]

   # 암호화 실행
   encrypted = encrypt_aes_cbc(json_str, key_base64, iv_base64)

   if encrypted:
       print("\nEncrypted (Base64):")
       print(encrypted)

if __name__ == "__main__":
   main()
