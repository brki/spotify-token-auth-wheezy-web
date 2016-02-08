import base64
from hashlib import sha256
import json
import requests

from wheezy.http import HTTPResponse
from wheezy.http import WSGIApplication
from wheezy.http import bad_request
from wheezy.routing import url
from wheezy.security.crypto import Ticket
from wheezy.web.middleware import bootstrap_defaults
from wheezy.web.middleware import path_routing_middleware_factory
from wheezy.web.handlers import BaseHandler

from spotifyauth.encryption import Encryption, DecryptionException
from spotifyauth import config


def extract_json_body_from_request(request):
    data = json.loads(request.form)
    return data


def bad_request_with_detail(message):
    response = bad_request()
    response.write(json.dumps({'error': message}))
    return response


crypt = Encryption(config.ENCRYPTION_KEY, salt=config.ENCRYPTION_SALT, encryption_style=config.ENCRYPTION_STYLE)
auth_header = {
    "Authorization": b"Basic " + base64.b64encode(config.SPOTIFY_CLIENT_ID + b":" + config.SPOTIFY_CLIENT_SECRET)
}

class RefreshHandler(BaseHandler):

    def post(self):

        try:
            form = self.request.form
            encrypted_token = form['token']
            token = crypt.decrypt(encrypted_token)
        except:
            return bad_request_with_detail('No data posted, or data in incorrect format')

        params = {
            "grant_type": "refresh_token",
            "refresh_token": token
        }

        token_response = requests.post(config.SPOTIFY_TOKEN_ENDPOINT,
                      data=params,
                      headers=auth_header,
                      verify=True)

        response = HTTPResponse()
        response.content_type = 'application/json'
        response.status_code = token_response.status_code
        response.write(token_response.content)
        return response


class SwapHandler(BaseHandler):

    def post(self):

        try:
            form = self.request.form
            code = form['code'][0]
        except:
            return bad_request_with_detail('No data posted, or data in incorrect format')


        params = {
            "grant_type": "authorization_code",
            "redirect_uri": config.SPOTIFY_CALLBACK_URL,
            "code": code
        }

        token_response = requests.post(config.SPOTIFY_TOKEN_ENDPOINT,
                                       data=params,
                                       headers=auth_header,
                                       verify=True)

        if token_response.status_code == 200:
            json_response = token_response.json()
            refresh_token = json_response["refresh_token"]
            encrypted_token = crypt.encrypt(refresh_token)
            json_response["refresh_token"] = encrypted_token
            response_body = json.dumps(json_response)
        else:
            response_body = token_response.content

        response = HTTPResponse()
        response.content_type = 'application/json'
        response.status_code = token_response.status_code
        response.write(response_body)
        return response


all_urls = [
    url('refresh', RefreshHandler, name='refresh'),
    url('swap', SwapHandler, name='swap'),
]


options = {
    'render_template': None,
    'ticket': Ticket(digestmod=sha256)
}
main = WSGIApplication(
    middleware=[
        bootstrap_defaults(url_mapping=all_urls),
        path_routing_middleware_factory
    ],
    options=options
)


if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    try:
        print('Visit http://localhost:8080/')
        make_server('', 8080, main).serve_forever()
    except KeyboardInterrupt:
        pass
    print('\nThanks!')
