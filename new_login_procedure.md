Hi!

I've also got the issue similar to #22 (where the login flow was changed) and did a little bit of digging. I only got captcha once for a few sessions, so I couldn't look extensively into that, but it appears that the logic of the login flow with captcha is the same, so I reckon the captcha will still work. I haven't been able to login programmatically yet, but wanted to share what I've found so far.

1. If captcha exists, POST request to `/unisso/preValidVerifycode` with the captcha in the body as content-type form-urlencoded. Returns `"success"` or `"fail"` Same as before
2. POST request to `/rest/pvms/web/user/v1/migrateStatus` with `{ "userName": "email%40domain.com" }` in body as content-type JSON and the email/username is urlencoded. Returns `{ "code": -1 }`. Different from before
3. GET request to `/unisso/pubkey`. Returns a JSON with the public key using RSA with OAEP and SHA-384 padding, a version number, a timestamp and a bool `enableEncrypt`. Different from before
4. POST request to `/unisso/v3/validateUser.action` with query parameters `timeStamp` with the timestamp from step 3 (pubkey) and `nonce` with a random string of 32 or a couple fewer characters. The content-type of the body is JSON: `{ "organizationName": "", "username": "mail%40domain.com", "password": "encrypted password", "verifycode": "captcha code" }`. The encrypted password is generated using the public key from step 3, urlencoding the password, chunking that, and building an encrypted string. The JS function can be found in `/unisso/js/login.js` - I've pasted the relevant function below. An equivalent Python function is also pasted below - I was able to login with the encrypted password that the Python function generated, so I'm assuming I translated the function correctly. Returns this:
```json
{
    "errorCode": "470",
    "errorMsg": null,
    "redirectURL": null,
    "respMultiRegionName": [
        "-5",
        "/rest/dp/web/v1/auth/on-sso-credential-ready?ticket=blabla&regionName=region002"
    ],
    "verifyCodeCreate": true,
    "twoFactorStatus": null
}
```
Then do GET request to `"/rest/dp/web/v1/auth/on-sso-credential-ready?ticket=blabla&regionName=region002"`, which returns a location header, which is the webui


```js
function submitData(submitUserName, nationCode, multiregion) {
  preSubmit()
  var params=initParam(submitUserName, nationCode);
  var orgName=params.orgName;
  var usernameInp=params.usernameInp;
  var valueInp=params.valueInp;
  var verifycodeInp=params.verifycodeInp;
  var search=params.search;
  $.ajax({
    type: 'GET',
    url: "/unisso/pubkey",
    contentType: "application/json",
    dataType: "json",
    success: function (result, request) {
      if (result) {
        var data = initLoginUserInfo(orgName, usernameInp, valueInp, verifycodeInp, multiregion);
        if (result.enableEncrypt) {
          var pubKey = KEYUTIL.getKey(result.pubKey);
          var valueEncode = encodeURIComponent(valueInp);
          var encryptValue = "";
          for (var i = 0; i < valueEncode.length / 270; i++) {
            var currntValue = valueEncode.substr(i * 270, 270);
            var encryptValueCurrent = KJUR.crypto.Cipher.encrypt(currntValue, pubKey, "RSAOAEP384");
            encryptValue = encryptValue == "" ? "" : encryptValue + "00000001";
            encryptValue = encryptValue + hextob64(encryptValueCurrent);
          }
          data.password = encryptValue + result.version;
        }
        if ($('#loginWithMessage').is(':visible')) {
          if (search === "") {
            search = "?step=phoneAndSmsLogin";
          } else {
            search = search + "&step=phoneAndSmsLogin";
          }
          data = dealLoginUserInfo(result, data, nationCodeSelect)
        }
        var URL = '/unisso/v2/validateUser.action' + search;
        if (result.enableEncrypt) {
          if (search === "") {
            URL = '/unisso/v3/validateUser.action'
                + "?timeStamp=" + result.timeStamp + "&nonce="
                + getSecureRandom();
          } else {
            URL = '/unisso/v3/validateUser.action' + search
                + "&timeStamp=" + result.timeStamp + "&nonce="
                + getSecureRandom();
          }
        }
      } else {
        var data = initLoginUserInfo(orgName, usernameInp, valueInp, verifycodeInp, multiregion);
        if ($('#loginWithMessage').is(':visible')) {
          search = search + "&step=phoneAndSmsLogin";
          data = dealLoginUserInfo(result, data, nationCodeSelect)
        }
        var URL = '/unisso/validateUser.action' + search;
      }
      var loginUserInfo = JSON.stringify(data);
      ajaxPost(URL, loginUserInfo, true);
    },
    error: function (xhr, ajaxOptions, thrownError) {
      enableBtn();
      showErrorMessage(connectionErrorMsg);
    }
  });
}
``` 



```python
# requires cryptography library from https://pypi.org/project/cryptography/

import base64
import urllib.parse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend


def rsa_encrypt_oaep_384(public_key, data_to_encrypt):
    """
    Encrypts data using RSA with OAEP and SHA-384 padding.

    :param public_key: A string containing the PEM-formatted public key, from the pubkey request.
    :param data_to_encrypt: Data to be encrypted (bytes or string).
    :return: Encrypted data as bytes.
    """
    public_key = load_pem_public_key(public_key.encode(), backend=default_backend())

    if isinstance(data_to_encrypt, str):
        data_to_encrypt = data_to_encrypt.encode()

    encrypted_data = public_key.encrypt(
        data_to_encrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None
        )
    )
    return encrypted_data

def encrypt_and_format_data(public_key, password, version):
    """
    Encrypts the provided value in chunks and formats it similarly to the JavaScript implementation.

    :param public_key: PEM-formatted public key, from the pubkey request.
    :param password: The password to be encrypted.
    :param version: The version string to be appended to the encrypted data, from the pubkey request.
    :return: The formatted encrypted value as a string.
    """
    value_encode = urllib.parse.quote_plus(password)
    encrypted_value = ""

    for i in range(0, len(value_encode), 270):
        current_value = value_encode[i:i + 270]
        encrypted_chunk = rsa_encrypt_oaep_384(public_key, current_value)
        encrypted_chunk_b64 = base64.b64encode(encrypted_chunk).decode()
        encrypted_value = encrypted_value + ("00000001" if encrypted_value else "") + encrypted_chunk_b64

    encrypted_value_with_version = encrypted_value + version

    return encrypted_value_with_version
```