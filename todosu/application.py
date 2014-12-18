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

import json

app = Flask(__name__, static_url_path='')
app.debug = True

from flask_oauth import OAuth

REDIRECT_URI = "/oauth2callback"
app.REDIRECT_URI = REDIRECT_URI# one of the Redirect URIs from Google APIs console

TODOS = []
google = None
def init():
    with open('auth_file.json') as f:
        auth = json.load(f)

        app.secret_key = auth['client_secret']
        oauth = OAuth()
        global google
        google = oauth.remote_app('google',
                                base_url='https://www.google.com/accounts/',
                                authorize_url=auth['auth_uri'],
                                request_token_url=None,
                                request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                        'response_type': 'code'},
                                access_token_url=auth['token_uri'],
                                access_token_method='POST',
                                access_token_params={'grant_type': 'authorization_code'},
                                consumer_key=auth['client_id'],
                                consumer_secret=auth['client_secret'])

init()


@app.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()

    todos = filter(None, TODOS)
    print 'Todos', todos
    return render_template('index.html', todos=todos)
    #return res.read()

@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)

@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('index'))

@google.tokengetter
def get_access_token():
    return session._get('access_token')


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

if __name__ == '__main__':
    app.config.update(
        DEBUG=True,
        PROPAGATE_EXCEPTIONS=True)
    app.run()
