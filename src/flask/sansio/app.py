from __future__ import annotations
import logging
import os
import sys
import typing as t
from datetime import timedelta
from itertools import chain
from werkzeug.exceptions import Aborter
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import BadRequestKeyError
from werkzeug.routing import BuildError
from werkzeug.routing import Map
from werkzeug.routing import Rule
from werkzeug.sansio.response import Response
from werkzeug.utils import cached_property
from werkzeug.utils import redirect as _wz_redirect
from .. import typing as ft
from ..config import Config
from ..config import ConfigAttribute
from ..ctx import _AppCtxGlobals
from ..helpers import _split_blueprint_path
from ..helpers import get_debug_flag
from ..json.provider import DefaultJSONProvider
from ..json.provider import JSONProvider
from ..logging import create_logger
from ..templating import DispatchingJinjaLoader
from ..templating import Environment
from .scaffold import _endpoint_from_view_func
from .scaffold import find_package
from .scaffold import Scaffold
from .scaffold import setupmethod
if t.TYPE_CHECKING:
    from werkzeug.wrappers import Response as BaseResponse
    from ..testing import FlaskClient
    from ..testing import FlaskCliRunner
    from .blueprints import Blueprint
T_shell_context_processor = t.TypeVar('T_shell_context_processor', bound=ft.ShellContextProcessorCallable)
T_teardown = t.TypeVar('T_teardown', bound=ft.TeardownCallable)
T_template_filter = t.TypeVar('T_template_filter', bound=ft.TemplateFilterCallable)
T_template_global = t.TypeVar('T_template_global', bound=ft.TemplateGlobalCallable)
T_template_test = t.TypeVar('T_template_test', bound=ft.TemplateTestCallable)

class App(Scaffold):
    """The flask object implements a WSGI application and acts as the central
    object.  It is passed the name of the module or package of the
    application.  Once it is created it will act as a central registry for
    the view functions, the URL rules, template configuration and much more.

    The name of the package is used to resolve resources from inside the
    package or the folder the module is contained in depending on if the
    package parameter resolves to an actual python package (a folder with
    an :file:`__init__.py` file inside) or a standard module (just a ``.py`` file).

    For more information about resource loading, see :func:`open_resource`.

    Usually you create a :class:`Flask` instance in your main module or
    in the :file:`__init__.py` file of your package like this::

        from flask import Flask
        app = Flask(__name__)

    .. admonition:: About the First Parameter

        The idea of the first parameter is to give Flask an idea of what
        belongs to your application.  This name is used to find resources
        on the filesystem, can be used by extensions to improve debugging
        information and a lot more.

        So it's important what you provide there.  If you are using a single
        module, `__name__` is always the correct value.  If you however are
        using a package, it's usually recommended to hardcode the name of
        your package there.

        For example if your application is defined in :file:`yourapplication/app.py`
        you should create it with one of the two versions below::

            app = Flask('yourapplication')
            app = Flask(__name__.split('.')[0])

        Why is that?  The application will work even with `__name__`, thanks
        to how resources are looked up.  However it will make debugging more
        painful.  Certain extensions can make assumptions based on the
        import name of your application.  For example the Flask-SQLAlchemy
        extension will look for the code in your application that triggered
        an SQL query in debug mode.  If the import name is not properly set
        up, that debugging information is lost.  (For example it would only
        pick up SQL queries in `yourapplication.app` and not
        `yourapplication.views.frontend`)

    .. versionadded:: 0.7
       The `static_url_path`, `static_folder`, and `template_folder`
       parameters were added.

    .. versionadded:: 0.8
       The `instance_path` and `instance_relative_config` parameters were
       added.

    .. versionadded:: 0.11
       The `root_path` parameter was added.

    .. versionadded:: 1.0
       The ``host_matching`` and ``static_host`` parameters were added.

    .. versionadded:: 1.0
       The ``subdomain_matching`` parameter was added. Subdomain
       matching needs to be enabled manually now. Setting
       :data:`SERVER_NAME` does not implicitly enable it.

    :param import_name: the name of the application package
    :param static_url_path: can be used to specify a different path for the
                            static files on the web.  Defaults to the name
                            of the `static_folder` folder.
    :param static_folder: The folder with static files that is served at
        ``static_url_path``. Relative to the application ``root_path``
        or an absolute path. Defaults to ``'static'``.
    :param static_host: the host to use when adding the static route.
        Defaults to None. Required when using ``host_matching=True``
        with a ``static_folder`` configured.
    :param host_matching: set ``url_map.host_matching`` attribute.
        Defaults to False.
    :param subdomain_matching: consider the subdomain relative to
        :data:`SERVER_NAME` when matching routes. Defaults to False.
    :param template_folder: the folder that contains the templates that should
                            be used by the application.  Defaults to
                            ``'templates'`` folder in the root path of the
                            application.
    :param instance_path: An alternative instance path for the application.
                          By default the folder ``'instance'`` next to the
                          package or module is assumed to be the instance
                          path.
    :param instance_relative_config: if set to ``True`` relative filenames
                                     for loading the config are assumed to
                                     be relative to the instance path instead
                                     of the application root.
    :param root_path: The path to the root of the application files.
        This should only be set manually when it can't be detected
        automatically, such as for namespace packages.
    """
    aborter_class = Aborter
    jinja_environment = Environment
    app_ctx_globals_class = _AppCtxGlobals
    config_class = Config
    testing = ConfigAttribute[bool]('TESTING')
    secret_key = ConfigAttribute[t.Union[str, bytes, None]]('SECRET_KEY')
    permanent_session_lifetime = ConfigAttribute[timedelta]('PERMANENT_SESSION_LIFETIME', get_converter=_make_timedelta)
    json_provider_class: type[JSONProvider] = DefaultJSONProvider
    "A subclass of :class:`~flask.json.provider.JSONProvider`. An\n    instance is created and assigned to :attr:`app.json` when creating\n    the app.\n\n    The default, :class:`~flask.json.provider.DefaultJSONProvider`, uses\n    Python's built-in :mod:`json` library. A different provider can use\n    a different JSON library.\n\n    .. versionadded:: 2.2\n    "
    jinja_options: dict[str, t.Any] = {}
    url_rule_class = Rule
    url_map_class = Map
    test_client_class: type[FlaskClient] | None = None
    test_cli_runner_class: type[FlaskCliRunner] | None = None
    default_config: dict[str, t.Any]
    response_class: type[Response]

    def __init__(self, import_name: str, static_url_path: str | None=None, static_folder: str | os.PathLike[str] | None='static', static_host: str | None=None, host_matching: bool=False, subdomain_matching: bool=False, template_folder: str | os.PathLike[str] | None='templates', instance_path: str | None=None, instance_relative_config: bool=False, root_path: str | None=None):
        super().__init__(import_name=import_name, static_folder=static_folder, static_url_path=static_url_path, template_folder=template_folder, root_path=root_path)
        if instance_path is None:
            instance_path = self.auto_find_instance_path()
        elif not os.path.isabs(instance_path):
            raise ValueError('If an instance path is provided it must be absolute. A relative path was given instead.')
        self.instance_path = instance_path
        self.config = self.make_config(instance_relative_config)
        self.aborter = self.make_aborter()
        self.json: JSONProvider = self.json_provider_class(self)
        "Provides access to JSON methods. Functions in ``flask.json``\n        will call methods on this provider when the application context\n        is active. Used for handling JSON requests and responses.\n\n        An instance of :attr:`json_provider_class`. Can be customized by\n        changing that attribute on a subclass, or by assigning to this\n        attribute afterwards.\n\n        The default, :class:`~flask.json.provider.DefaultJSONProvider`,\n        uses Python's built-in :mod:`json` library. A different provider\n        can use a different JSON library.\n\n        .. versionadded:: 2.2\n        "
        self.url_build_error_handlers: list[t.Callable[[Exception, str, dict[str, t.Any]], str]] = []
        self.teardown_appcontext_funcs: list[ft.TeardownCallable] = []
        self.shell_context_processors: list[ft.ShellContextProcessorCallable] = []
        self.blueprints: dict[str, Blueprint] = {}
        self.extensions: dict[str, t.Any] = {}
        self.url_map = self.url_map_class(host_matching=host_matching)
        self.subdomain_matching = subdomain_matching
        self._got_first_request = False

    @cached_property
    def name(self) -> str:
        """The name of the application.  This is usually the import name
        with the difference that it's guessed from the run file if the
        import name is main.  This name is used as a display name when
        Flask needs the name of the application.  It can be set and overridden
        to change the value.

        .. versionadded:: 0.8
        """
        if self.import_name == '__main__':
            fn = getattr(sys.modules['__main__'], '__file__', None)
            if fn is None:
                return '__main__'
            return os.path.splitext(os.path.basename(fn))[0]
        return self.import_name

    @cached_property
    def logger(self) -> logging.Logger:
        """A standard Python :class:`~logging.Logger` for the app, with
        the same name as :attr:`name`.

        In debug mode, the logger's :attr:`~logging.Logger.level` will
        be set to :data:`~logging.DEBUG`.

        If there are no handlers configured, a default handler will be
        added. See :doc:`/logging` for more information.

        .. versionchanged:: 1.1.0
            The logger takes the same name as :attr:`name` rather than
            hard-coding ``"flask.app"``.

        .. versionchanged:: 1.0.0
            Behavior was simplified. The logger is always named
            ``"flask.app"``. The level is only set during configuration,
            it doesn't check ``app.debug`` each time. Only one format is
            used, not different ones depending on ``app.debug``. No
            handlers are removed, and a handler is only added if no
            handlers are already configured.

        .. versionadded:: 0.3
        """
        return create_logger(self)

    @cached_property
    def jinja_env(self) -> Environment:
        """The Jinja environment used to load templates.

        The environment is created the first time this property is
        accessed. Changing :attr:`jinja_options` after that will have no
        effect.
        """
        return self.create_jinja_environment()

    def make_config(self, instance_relative: bool=False) -> Config:
        """Used to create the config attribute by the Flask constructor.
        The `instance_relative` parameter is passed in from the constructor
        of Flask (there named `instance_relative_config`) and indicates if
        the config should be relative to the instance path or the root path
        of the application.

        .. versionadded:: 0.8
        """
        root_path = self.root_path
        if instance_relative:
            root_path = self.instance_path
        return self.config_class(root_path, self.default_config)

    def make_aborter(self) -> Aborter:
        """Create the object to assign to :attr:`aborter`. That object
        is called by :func:`flask.abort` to raise HTTP errors, and can
        be called directly as well.

        By default, this creates an instance of :attr:`aborter_class`,
        which defaults to :class:`werkzeug.exceptions.Aborter`.

        .. versionadded:: 2.2
        """
        return self.aborter_class()

    def auto_find_instance_path(self) -> str:
        """Tries to locate the instance path if it was not provided to the
        constructor of the application class.  It will basically calculate
        the path to a folder named ``instance`` next to your main file or
        the package.

        .. versionadded:: 0.8
        """
        prefix, package_path = find_package(self.import_name)
        if prefix is None:
            return os.path.join(package_path, 'instance')
        return os.path.join(prefix, 'var', self.name + '-instance')

    def create_global_jinja_loader(self) -> DispatchingJinjaLoader:
        """Creates the loader for the Jinja2 environment.  Can be used to
        override just the loader and keeping the rest unchanged.  It's
        discouraged to override this function.  Instead one should override
        the :meth:`jinja_loader` function instead.

        The global loader dispatches between the loaders of the application
        and the individual blueprints.

        .. versionadded:: 0.7
        """
        return DispatchingJinjaLoader(self)

    def select_jinja_autoescape(self, filename: str) -> bool:
        """Returns ``True`` if autoescaping should be active for the given
        template name. If no template name is given, returns `True`.

        .. versionchanged:: 2.2
            Autoescaping is now enabled by default for ``.svg`` files.

        .. versionadded:: 0.5
        """
        if filename is None:
            return True
        return filename.endswith(('.html', '.htm', '.xml', '.xhtml', '.svg'))

    @property
    def debug(self) -> bool:
        """Whether debug mode is enabled. When using ``flask run`` to start the
        development server, an interactive debugger will be shown for unhandled
        exceptions, and the server will be reloaded when code changes. This maps to the
        :data:`DEBUG` config key. It may not behave as expected if set late.

        **Do not enable debug mode when deploying in production.**

        Default: ``False``
        """
        return self.config['DEBUG']

    @debug.setter
    def debug(self, value: bool) -> None:
        self.config['DEBUG'] = value
        self.jinja_env.auto_reload = self.templates_auto_reload

    @setupmethod
    def register_blueprint(self, blueprint: Blueprint, **options: t.Any) -> None:
        """Register a :class:`~flask.Blueprint` on the application. Keyword
        arguments passed to this method will override the defaults set on the
        blueprint.

        Calls the blueprint's :meth:`~flask.Blueprint.register` method after
        recording the blueprint in the application's :attr:`blueprints`.

        :param blueprint: The blueprint to register.
        :param url_prefix: Blueprint routes will be prefixed with this.
        :param subdomain: Blueprint routes will match on this subdomain.
        :param url_defaults: Blueprint routes will use these default values for
            view arguments.
        :param options: Additional keyword arguments are passed to
            :class:`~flask.blueprints.BlueprintSetupState`. They can be
            accessed in :meth:`~flask.Blueprint.record` callbacks.

        .. versionchanged:: 2.0.1
            The ``name`` option can be used to change the (pre-dotted)
            name the blueprint is registered with. This allows the same
            blueprint to be registered multiple times with unique names
            for ``url_for``.

        .. versionadded:: 0.7
        """
        pass

    def iter_blueprints(self) -> t.ValuesView[Blueprint]:
        """Iterates over all blueprints by the order they were registered.

        .. versionadded:: 0.11
        """
        pass

    @setupmethod
    def template_filter(self, name: str | None=None) -> t.Callable[[T_template_filter], T_template_filter]:
        """A decorator that is used to register custom template filter.
        You can specify a name for the filter, otherwise the function
        name will be used. Example::

          @app.template_filter()
          def reverse(s):
              return s[::-1]

        :param name: the optional name of the filter, otherwise the
                     function name will be used.
        """
        pass

    @setupmethod
    def add_template_filter(self, f: ft.TemplateFilterCallable, name: str | None=None) -> None:
        """Register a custom template filter.  Works exactly like the
        :meth:`template_filter` decorator.

        :param name: the optional name of the filter, otherwise the
                     function name will be used.
        """
        pass

    @setupmethod
    def template_test(self, name: str | None=None) -> t.Callable[[T_template_test], T_template_test]:
        """A decorator that is used to register custom template test.
        You can specify a name for the test, otherwise the function
        name will be used. Example::

          @app.template_test()
          def is_prime(n):
              if n == 2:
                  return True
              for i in range(2, int(math.ceil(math.sqrt(n))) + 1):
                  if n % i == 0:
                      return False
              return True

        .. versionadded:: 0.10

        :param name: the optional name of the test, otherwise the
                     function name will be used.
        """
        pass

    @setupmethod
    def add_template_test(self, f: ft.TemplateTestCallable, name: str | None=None) -> None:
        """Register a custom template test.  Works exactly like the
        :meth:`template_test` decorator.

        .. versionadded:: 0.10

        :param name: the optional name of the test, otherwise the
                     function name will be used.
        """
        pass

    @setupmethod
    def template_global(self, name: str | None=None) -> t.Callable[[T_template_global], T_template_global]:
        """A decorator that is used to register a custom template global function.
        You can specify a name for the global function, otherwise the function
        name will be used. Example::

            @app.template_global()
            def double(n):
                return 2 * n

        .. versionadded:: 0.10

        :param name: the optional name of the global function, otherwise the
                     function name will be used.
        """
        pass

    @setupmethod
    def add_template_global(self, f: ft.TemplateGlobalCallable, name: str | None=None) -> None:
        """Register a custom template global function. Works exactly like the
        :meth:`template_global` decorator.

        .. versionadded:: 0.10

        :param name: the optional name of the global function, otherwise the
                     function name will be used.
        """
        pass

    @setupmethod
    def teardown_appcontext(self, f: T_teardown) -> T_teardown:
        """Registers a function to be called when the application
        context is popped. The application context is typically popped
        after the request context for each request, at the end of CLI
        commands, or after a manually pushed context ends.

        .. code-block:: python

            with app.app_context():
                ...

        When the ``with`` block exits (or ``ctx.pop()`` is called), the
        teardown functions are called just before the app context is
        made inactive. Since a request context typically also manages an
        application context it would also be called when you pop a
        request context.

        When a teardown function was called because of an unhandled
        exception it will be passed an error object. If an
        :meth:`errorhandler` is registered, it will handle the exception
        and the teardown will not receive it.

        Teardown functions must avoid raising exceptions. If they
        execute code that might fail they must surround that code with a
        ``try``/``except`` block and log any errors.

        The return values of teardown functions are ignored.

        .. versionadded:: 0.9
        """
        pass

    @setupmethod
    def shell_context_processor(self, f: T_shell_context_processor) -> T_shell_context_processor:
        """Registers a shell context processor function.

        .. versionadded:: 0.11
        """
        pass

    def _find_error_handler(self, e: Exception, blueprints: list[str]) -> ft.ErrorHandlerCallable | None:
        """Return a registered error handler for an exception in this order:
        blueprint handler for a specific code, app handler for a specific code,
        blueprint handler for an exception class, app handler for an exception
        class, or ``None`` if a suitable handler is not found.
        """
        pass

    def trap_http_exception(self, e: Exception) -> bool:
        """Checks if an HTTP exception should be trapped or not.  By default
        this will return ``False`` for all exceptions except for a bad request
        key error if ``TRAP_BAD_REQUEST_ERRORS`` is set to ``True``.  It
        also returns ``True`` if ``TRAP_HTTP_EXCEPTIONS`` is set to ``True``.

        This is called for all HTTP exceptions raised by a view function.
        If it returns ``True`` for any exception the error handler for this
        exception is not called and it shows up as regular exception in the
        traceback.  This is helpful for debugging implicitly raised HTTP
        exceptions.

        .. versionchanged:: 1.0
            Bad request errors are not trapped by default in debug mode.

        .. versionadded:: 0.8
        """
        pass

    def should_ignore_error(self, error: BaseException | None) -> bool:
        """This is called to figure out if an error should be ignored
        or not as far as the teardown system is concerned.  If this
        function returns ``True`` then the teardown handlers will not be
        passed the error.

        .. versionadded:: 0.10
        """
        pass

    def redirect(self, location: str, code: int=302) -> BaseResponse:
        """Create a redirect response object.

        This is called by :func:`flask.redirect`, and can be called
        directly as well.

        :param location: The URL to redirect to.
        :param code: The status code for the redirect.

        .. versionadded:: 2.2
            Moved from ``flask.redirect``, which calls this method.
        """
        pass

    def inject_url_defaults(self, endpoint: str, values: dict[str, t.Any]) -> None:
        """Injects the URL defaults for the given endpoint directly into
        the values dictionary passed.  This is used internally and
        automatically called on URL building.

        .. versionadded:: 0.7
        """
        pass

    def handle_url_build_error(self, error: BuildError, endpoint: str, values: dict[str, t.Any]) -> str:
        """Called by :meth:`.url_for` if a
        :exc:`~werkzeug.routing.BuildError` was raised. If this returns
        a value, it will be returned by ``url_for``, otherwise the error
        will be re-raised.

        Each function in :attr:`url_build_error_handlers` is called with
        ``error``, ``endpoint`` and ``values``. If a function returns
        ``None`` or raises a ``BuildError``, it is skipped. Otherwise,
        its return value is returned by ``url_for``.

        :param error: The active ``BuildError`` being handled.
        :param endpoint: The endpoint being built.
        :param values: The keyword arguments passed to ``url_for``.
        """
        pass
