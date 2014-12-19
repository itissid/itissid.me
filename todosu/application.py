from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    session
)
from requests_oauthlib import OAuth2Session

from optparse import OptionParser
import json
from functools import wraps
import os

app = Flask(__name__, static_url_path='')

# REDIRECT_URI = "/oauth2callback"
# app.REDIRECT_URI = REDIRECT_URI# one of the Redirect URIs from Google APIs console

TODOS = []
# google = None


# Just the config for oauth in the deployed file
def get_oath_config(func):
    @wraps(func)
    def inner(*args, **kwargs):
        with open('auth_file.json') as f:
            auth = json.load(f)
            from collections import namedtuple
            oath_object = namedtuple(
                'Oauth', [
                    'provider', 'client_id', 'client_secret', 'redirect_uri',
                    'authorization_base_url', 'token_url',
                    'scope', 'user_info_uri'])
            app.secret_key = auth['client_secret']
            google_oauth_obj = oath_object(
                provider = 'Google',
                client_id = auth['client_id'],
                client_secret = auth['client_secret'],
                redirect_uri = auth['redirect_uris'][env],

                # OAuth endpoints given in the Google API documentation
                authorization_base_url = auth['authorization_base_url'],
                token_url = auth['token_uri'],
                scope = [
                        "https://www.googleapis.com/auth/userinfo.email"
                ],
                user_info_uri = auth['user_info_uri']
            )
            kwargs['oauth_config'] = google_oauth_obj
            return func(*args, **kwargs)
    return inner


@app.route('/')
@get_oath_config
def index(oauth_config):
    # If we already have the access token we can fetch resources.
    # This means step 3 of the 3 legged oauth handshake was completed.
    oauth_token = session.get('oauth_token')
    if oauth_token is None:
        return redirect(url_for('authorization'))

    # Back here after step 3
    try:
        google = OAuth2Session(
            client_id=oauth_config.client_id, token=oauth_token)
        user_info_response = google.get(oauth_config.user_info_uri)
    except:
        session['oauth_token'] = google.refresh_token(
                oauth_config.auth_uri, client_id=oauth_config.client_id,
                client_secret=oauth_config.client_secret)
        google = OAuth2Session(oauth_config.client_id, token=token)
        user_info_response = google.get(oauth_config.user_info_uri)

    todos = filter(None, TODOS)
    return render_template(
        'index.html', todos=todos, user_info=user_info_response.json())


@app.route('/authorization')
@get_oath_config
def authorization(oauth_config):
    google = OAuth2Session(
        oauth_config.client_id, scope=oauth_config.scope,
        redirect_uri=oauth_config.redirect_uri)

    # Redirect user to Google for authorization
    authorization_url, state = google.authorization_url(
        oauth_config.authorization_base_url,
        # online for refresh token
        # force to always make user click authorize
        access_type="online")
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/oauth2callback', methods=["GET"])
@get_oath_config
def authorized(oauth_config):
    # Note that the full callbackurl from the OAuth provider
    # google, facebook etc will be in the request
    google = OAuth2Session(
        oauth_config.client_id, scope=oauth_config.scope,
        redirect_uri=oauth_config.redirect_uri)
    token = google.fetch_token(
         oauth_config.token_url, client_secret=oauth_config.client_secret,
         authorization_response=request.url)
    session['oauth_token'] = token
    return redirect(url_for('index'))


@app.route('/todos/', methods=['POST'])
def todo_create():
    todo = request.get_json()
    todo['id'] = len(TODOS)
    TODOS.append(todo)
    return _todo_response(todo)


@app.route('/todos/<int:id>')
def todo_read(id):
    todo = _todo_get_or_404(id)
    return _todo_response(todo)


@app.route('/todos/<int:id>', methods=['PUT', 'PATCH'])
def todo_update(id):
    todo = _todo_get_or_404(id)
    updates = request.get_json()
    print updates
    todo.update(updates)
    return _todo_response(todo)


@app.route('/todos/<int:id>', methods=['DELETE'])
def todo_delete(id):
    todo = _todo_get_or_404(id)
    TODOS[id] = None
    return _todo_response(todo)


def _todo_get_or_404(id):
    if not (0 <= id < len(TODOS)):
        abort(404)
    todo = TODOS[id]
    if todo is None:
        abort(404)
    return todo


def _todo_response(todo):
    return jsonify(**todo)


def get_cli_options():
    """
    Return the work environment
    """
    usage = "usage: %prog options"
    parser = OptionParser(usage=usage)
    parser.add_option(
        '-e', '--env', type='choice', action='store', dest='environment',
        choices=['production', 'dev'], default='dev',
        help='Environment to run on')
    parser.add_option('-d', dest="debug", action="store_true",
                      help = "Turn debugging on for the webserver")
    return parser.parse_args()

if __name__ == '__main__':
    options, args = get_cli_options()
    global env
    env = options.environment
    if env is None:
        raise ValueError('Environment has to be set to one of '
                         'dev or prod')

    print "Debugging option for web server is: ", options.debug
    app.config.update(
        DEBUG=True if options.debug else False,
        PROPAGATE_EXCEPTIONS=True if options.debug else False)
    # TODO: Remove these once HTTPS is active
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = 'True'
    app.run()
