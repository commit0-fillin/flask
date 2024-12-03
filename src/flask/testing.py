from __future__ import annotations
import importlib.metadata
import typing as t
from contextlib import contextmanager
from contextlib import ExitStack
from copy import copy
from types import TracebackType
from urllib.parse import urlsplit
import werkzeug.test
from click.testing import CliRunner
from werkzeug.test import Client
from werkzeug.wrappers import Request as BaseRequest
from .cli import ScriptInfo
from .sessions import SessionMixin
if t.TYPE_CHECKING:
    from _typeshed.wsgi import WSGIEnvironment
    from werkzeug.test import TestResponse
    from .app import Flask

class EnvironBuilder(werkzeug.test.EnvironBuilder):
    """An :class:`~werkzeug.test.EnvironBuilder`, that takes defaults from the
    application.

    :param app: The Flask application to configure the environment from.
    :param path: URL path being requested.
    :param base_url: Base URL where the app is being served, which
        ``path`` is relative to. If not given, built from
        :data:`PREFERRED_URL_SCHEME`, ``subdomain``,
        :data:`SERVER_NAME`, and :data:`APPLICATION_ROOT`.
    :param subdomain: Subdomain name to append to :data:`SERVER_NAME`.
    :param url_scheme: Scheme to use instead of
        :data:`PREFERRED_URL_SCHEME`.
    :param json: If given, this is serialized as JSON and passed as
        ``data``. Also defaults ``content_type`` to
        ``application/json``.
    :param args: other positional arguments passed to
        :class:`~werkzeug.test.EnvironBuilder`.
    :param kwargs: other keyword arguments passed to
        :class:`~werkzeug.test.EnvironBuilder`.
    """

    def __init__(self, app: Flask, path: str='/', base_url: str | None=None, subdomain: str | None=None, url_scheme: str | None=None, *args: t.Any, **kwargs: t.Any) -> None:
        assert not (base_url or subdomain or url_scheme) or (base_url is not None) != bool(subdomain or url_scheme), 'Cannot pass "subdomain" or "url_scheme" with "base_url".'
        if base_url is None:
            http_host = app.config.get('SERVER_NAME') or 'localhost'
            app_root = app.config['APPLICATION_ROOT']
            if subdomain:
                http_host = f'{subdomain}.{http_host}'
            if url_scheme is None:
                url_scheme = app.config['PREFERRED_URL_SCHEME']
            url = urlsplit(path)
            base_url = f'{url.scheme or url_scheme}://{url.netloc or http_host}/{app_root.lstrip('/')}'
            path = url.path
            if url.query:
                sep = b'?' if isinstance(url.query, bytes) else '?'
                path += sep + url.query
        self.app = app
        super().__init__(path, base_url, *args, **kwargs)

    def json_dumps(self, obj: t.Any, **kwargs: t.Any) -> str:
        """Serialize ``obj`` to a JSON-formatted string.

        The serialization will be configured according to the config associated
        with this EnvironBuilder's ``app``.
        """
        return self.app.json.dumps(obj, **kwargs)
_werkzeug_version = ''

class FlaskClient(Client):
    """Works like a regular Werkzeug test client but has knowledge about
    Flask's contexts to defer the cleanup of the request context until
    the end of a ``with`` block. For general information about how to
    use this class refer to :class:`werkzeug.test.Client`.

    .. versionchanged:: 0.12
       `app.test_client()` includes preset default environment, which can be
       set after instantiation of the `app.test_client()` object in
       `client.environ_base`.

    Basic usage is outlined in the :doc:`/testing` chapter.
    """
    application: Flask

    def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
        super().__init__(*args, **kwargs)
        self.preserve_context = False
        self._new_contexts: list[t.ContextManager[t.Any]] = []
        self._context_stack = ExitStack()
        self.environ_base = {'REMOTE_ADDR': '127.0.0.1', 'HTTP_USER_AGENT': f'Werkzeug/{_werkzeug_version}'}

    @contextmanager
    def session_transaction(self, *args: t.Any, **kwargs: t.Any) -> t.Iterator[SessionMixin]:
        """When used in combination with a ``with`` statement this opens a
        session transaction.  This can be used to modify the session that
        the test client uses.  Once the ``with`` block is left the session is
        stored back.

        ::

            with client.session_transaction() as session:
                session['value'] = 42

        Internally this is implemented by going through a temporary test
        request context and since session handling could depend on
        request variables this function accepts the same arguments as
        :meth:`~flask.Flask.test_request_context` which are directly
        passed through.
        """
        with self.application.test_request_context(*args, **kwargs):
            sess = self.application.session_interface.open_session(
                self.application, self.application.request
            )
            if sess is None:
                raise RuntimeError("Session handling is not configured.")
            yield sess
            resp = self.application.response_class()
            self.application.session_interface.save_session(self.application, sess, resp)

    def __enter__(self) -> FlaskClient:
        if self.preserve_context:
            raise RuntimeError('Cannot nest client invocations')
        self.preserve_context = True
        return self

    def __exit__(self, exc_type: type | None, exc_value: BaseException | None, tb: TracebackType | None) -> None:
        self.preserve_context = False
        self._context_stack.close()

class FlaskCliRunner(CliRunner):
    """A :class:`~click.testing.CliRunner` for testing a Flask app's
    CLI commands. Typically created using
    :meth:`~flask.Flask.test_cli_runner`. See :ref:`testing-cli`.
    """

    def __init__(self, app: Flask, **kwargs: t.Any) -> None:
        self.app = app
        super().__init__(**kwargs)

    def invoke(self, cli: t.Any=None, args: t.Any=None, **kwargs: t.Any) -> t.Any:
        """Invokes a CLI command in an isolated environment. See
        :meth:`CliRunner.invoke <click.testing.CliRunner.invoke>` for
        full method documentation. See :ref:`testing-cli` for examples.

        If the ``obj`` argument is not given, passes an instance of
        :class:`~flask.cli.ScriptInfo` that knows how to load the Flask
        app being tested.

        :param cli: Command object to invoke. Default is the app's
            :attr:`~flask.app.Flask.cli` group.
        :param args: List of strings to invoke the command with.

        :return: a :class:`~click.testing.Result` object.
        """
        if cli is None:
            cli = self.app.cli

        if "obj" not in kwargs:
            kwargs["obj"] = ScriptInfo(create_app=lambda: self.app)

        return super().invoke(cli, args, **kwargs)
