from flask import Flask
from flask import render_template
import utils


app = Flask(__name__)

import logging


@app.route('/')
def hello_world():
    """
    This is a test application
    """
    return render_template('index.html')


if __name__ == '__main__':
    app.config.update(
        DEBUG=True,
        PROPAGATE_EXCEPTIONS=True)
    app.run()
