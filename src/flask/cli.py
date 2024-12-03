from __future__ import annotations
import ast
import collections.abc as cabc
import importlib.metadata
import inspect
import os
import platform
import re
import sys
import traceback
import typing as t
from functools import update_wrapper
from operator import itemgetter
from types import ModuleType
import click
from click.core import ParameterSource
from werkzeug import run_simple
from werkzeug.serving import is_running_from_reloader
from werkzeug.utils import import_string
from .globals import current_app
from .helpers import get_debug_flag
from .helpers import get_load_dotenv
if t.TYPE_CHECKING:
    import ssl
    from _typeshed.wsgi import StartResponse
    from _typeshed.wsgi import WSGIApplication
    from _typeshed.wsgi import WSGIEnvironment
    from .app import Flask

class NoAppException(click.UsageError):
    """Raised if an application cannot be found or loaded."""

def find_best_app(module: ModuleType) -> Flask:
    """Given a module instance this tries to find the best possible
    application in the module or raises an exception.
    """
    from flask import Flask

    # Try to get an app instance directly from the module
    if hasattr(module, 'app') and isinstance(module.app, Flask):
        return module.app

    # Look for a 'create_app' or 'make_app' function
    for app_factory in ('create_app', 'make_app'):
        app_factory_func = getattr(module, app_factory, None)
        if app_factory_func and callable(app_factory_func):
            app = app_factory_func()
            if isinstance(app, Flask):
                return app

    # Look for an app instance in the module's attributes
    for name in dir(module):
        attr = getattr(module, name)
        if isinstance(attr, Flask):
            return attr

    raise NoAppException(
        "Failed to find Flask application or factory in module. "
        "Use 'FLASK_APP=filename:app' to specify one."
    )

def _called_with_wrong_args(f: t.Callable[..., Flask]) -> bool:
    """Check whether calling a function raised a ``TypeError`` because
    the call failed or because something in the factory raised the
    error.

    :param f: The function that was called.
    :return: ``True`` if the call failed.
    """
    try:
        f()
    except TypeError as e:
        tb = sys.exc_info()[2]
        if tb is not None and tb.tb_next is not None:
            # The traceback has more than one frame, so the error occurred
            # inside the function rather than during the function call
            return False
        return True
    except:
        # The function call succeeded, but the function itself raised a
        # different exception
        return False
    else:
        # The function call succeeded
        return False

def find_app_by_string(module: ModuleType, app_name: str) -> Flask:
    """Check if the given string is a variable name or a function. Call
    a function to get the app instance, or return the variable directly.
    """
    from flask import Flask

    # Check if the app_name refers to a variable in the module
    if hasattr(module, app_name):
        app = getattr(module, app_name)
        if isinstance(app, Flask):
            return app
        elif callable(app):
            app = app()
            if isinstance(app, Flask):
                return app

    # If not found, try to call it as a function
    try:
        app = getattr(module, app_name)()
        if isinstance(app, Flask):
            return app
    except TypeError:
        if _called_with_wrong_args(lambda: getattr(module, app_name)()):
            raise NoAppException(
                f"The factory '{app_name}' in module '{module.__name__}' "
                f"could not be called with the specified arguments."
            )
    except AttributeError:
        raise NoAppException(
            f"Failed to find application in module '{module.__name__}'. "
            f"The string '{app_name}' is not valid as a variable name "
            f"or function. Please specify a valid name or function."
        )

    raise NoAppException(
        f"A valid Flask application was not obtained from '{app_name}' "
        f"in module '{module.__name__}'."
    )

def prepare_import(path: str) -> str:
    """Given a filename this will try to calculate the python path, add it
    to the search path and return the actual module name that is expected.
    """
    path = os.path.realpath(path)

    if os.path.splitext(path)[1] == '.py':
        path = os.path.splitext(path)[0]

    if os.path.basename(path) == '__init__':
        path = os.path.dirname(path)

    module_name = []

    # move up until outside package structure (no __init__.py)
    while True:
        path, name = os.path.split(path)
        module_name.append(name)

        if not os.path.exists(os.path.join(path, '__init__.py')):
            break

    if sys.path[0] != path:
        sys.path.insert(0, path)

    return '.'.join(module_name[::-1])
version_option = click.Option(['--version'], help='Show the Flask version.', expose_value=False, callback=get_version, is_flag=True, is_eager=True)

class ScriptInfo:
    """Helper object to deal with Flask applications.  This is usually not
    necessary to interface with as it's used internally in the dispatching
    to click.  In future versions of Flask this object will most likely play
    a bigger role.  Typically it's created automatically by the
    :class:`FlaskGroup` but you can also manually create it and pass it
    onwards as click object.
    """

    def __init__(self, app_import_path: str | None=None, create_app: t.Callable[..., Flask] | None=None, set_debug_flag: bool=True) -> None:
        self.app_import_path = app_import_path
        self.create_app = create_app
        self.data: dict[t.Any, t.Any] = {}
        self.set_debug_flag = set_debug_flag
        self._loaded_app: Flask | None = None

    def load_app(self) -> Flask:
        """Loads the Flask app (if not yet loaded) and returns it.  Calling
        this multiple times will just result in the already loaded app to
        be returned.
        """
        if self._loaded_app is not None:
            return self._loaded_app

        if self.create_app is not None:
            app = self.create_app()
        else:
            if self.app_import_path:
                path, name = (
                    re.split(r":(?![\\/])", self.app_import_path, 1) + [None]
                )[:2]
                import_name = prepare_import(path)
                app = locate_app(import_name, name)
            else:
                for path in ("wsgi.py", "app.py"):
                    import_name = prepare_import(path)
                    app = locate_app(import_name)
                    if app:
                        break

        if not app:
            raise NoAppException(
                "Could not locate a Flask application. You did not provide "
                "the 'FLASK_APP' environment variable, and a 'wsgi.py' or "
                "'app.py' module was not found in the current directory."
            )

        if self.set_debug_flag:
            # Update the app's debug flag through the descriptor so that
            # other values repopulate as well.
            app.debug = get_debug_flag()

        self._loaded_app = app
        return app
pass_script_info = click.make_pass_decorator(ScriptInfo, ensure=True)
F = t.TypeVar('F', bound=t.Callable[..., t.Any])

def with_appcontext(f: F) -> F:
    """Wraps a callback so that it's guaranteed to be executed with the
    script's application context.

    Custom commands (and their options) registered under ``app.cli`` or
    ``blueprint.cli`` will always have an app context available, this
    decorator is not required in that case.

    .. versionchanged:: 2.2
        The app context is active for subcommands as well as the
        decorated callback. The app context is always available to
        ``app.cli`` command and parameter callbacks.
    """
    @click.pass_context
    def decorator(__ctx, *args, **kwargs):
        with __ctx.ensure_object(ScriptInfo).load_app().app_context():
            return __ctx.invoke(f, *args, **kwargs)
    return t.cast(F, update_wrapper(decorator, f))

class AppGroup(click.Group):
    """This works similar to a regular click :class:`~click.Group` but it
    changes the behavior of the :meth:`command` decorator so that it
    automatically wraps the functions in :func:`with_appcontext`.

    Not to be confused with :class:`FlaskGroup`.
    """

    def command(self, *args: t.Any, **kwargs: t.Any) -> t.Callable[[t.Callable[..., t.Any]], click.Command]:
        """This works exactly like the method of the same name on a regular
        :class:`click.Group` but it wraps callbacks in :func:`with_appcontext`
        unless it's disabled by passing ``with_appcontext=False``.
        """
        wrap_for_ctx = kwargs.pop("with_appcontext", True)

        def decorator(f):
            if wrap_for_ctx:
                f = with_appcontext(f)
            return click.Group.command(self, *args, **kwargs)(f)

        return decorator

    def group(self, *args: t.Any, **kwargs: t.Any) -> t.Callable[[t.Callable[..., t.Any]], click.Group]:
        """This works exactly like the method of the same name on a regular
        :class:`click.Group` but it defaults the group class to
        :class:`AppGroup`.
        """
        kwargs.setdefault('cls', AppGroup)
        return super().group(*args, **kwargs)
_app_option = click.Option(['-A', '--app'], metavar='IMPORT', help="The Flask application or factory function to load, in the form 'module:name'. Module can be a dotted import or file path. Name is not required if it is 'app', 'application', 'create_app', or 'make_app', and can be 'name(args)' to pass arguments.", is_eager=True, expose_value=False, callback=_set_app)
_debug_option = click.Option(['--debug/--no-debug'], help='Set debug mode.', expose_value=False, callback=_set_debug)
_env_file_option = click.Option(['-e', '--env-file'], type=click.Path(exists=True, dir_okay=False), help='Load environment variables from this file. python-dotenv must be installed.', is_eager=True, expose_value=False, callback=_env_file_callback)

class FlaskGroup(AppGroup):
    """Special subclass of the :class:`AppGroup` group that supports
    loading more commands from the configured Flask app.  Normally a
    developer does not have to interface with this class but there are
    some very advanced use cases for which it makes sense to create an
    instance of this. see :ref:`custom-scripts`.

    :param add_default_commands: if this is True then the default run and
        shell commands will be added.
    :param add_version_option: adds the ``--version`` option.
    :param create_app: an optional callback that is passed the script info and
        returns the loaded app.
    :param load_dotenv: Load the nearest :file:`.env` and :file:`.flaskenv`
        files to set environment variables. Will also change the working
        directory to the directory containing the first file found.
    :param set_debug_flag: Set the app's debug flag.

    .. versionchanged:: 2.2
        Added the ``-A/--app``, ``--debug/--no-debug``, ``-e/--env-file`` options.

    .. versionchanged:: 2.2
        An app context is pushed when running ``app.cli`` commands, so
        ``@with_appcontext`` is no longer required for those commands.

    .. versionchanged:: 1.0
        If installed, python-dotenv will be used to load environment variables
        from :file:`.env` and :file:`.flaskenv` files.
    """

    def __init__(self, add_default_commands: bool=True, create_app: t.Callable[..., Flask] | None=None, add_version_option: bool=True, load_dotenv: bool=True, set_debug_flag: bool=True, **extra: t.Any) -> None:
        params = list(extra.pop('params', None) or ())
        params.extend((_env_file_option, _app_option, _debug_option))
        if add_version_option:
            params.append(version_option)
        if 'context_settings' not in extra:
            extra['context_settings'] = {}
        extra['context_settings'].setdefault('auto_envvar_prefix', 'FLASK')
        super().__init__(params=params, **extra)
        self.create_app = create_app
        self.load_dotenv = load_dotenv
        self.set_debug_flag = set_debug_flag
        if add_default_commands:
            self.add_command(run_command)
            self.add_command(shell_command)
            self.add_command(routes_command)
        self._loaded_plugin_commands = False

def _path_is_ancestor(path: str, other: str) -> bool:
    """Take ``other`` and remove the length of ``path`` from it. Then join it
    to ``path``. If it is the original value, ``path`` is an ancestor of
    ``other``."""
    path = os.path.normpath(path)
    other = os.path.normpath(other)
    return os.path.join(path, other[len(path):].lstrip(os.sep)) == other

def load_dotenv(path: str | os.PathLike[str] | None=None) -> bool:
    """Load "dotenv" files in order of precedence to set environment variables.

    If an env var is already set it is not overwritten, so earlier files in the
    list are preferred over later files.

    This is a no-op if `python-dotenv`_ is not installed.

    .. _python-dotenv: https://github.com/theskumar/python-dotenv#readme

    :param path: Load the file at this location instead of searching.
    :return: ``True`` if a file was loaded.

    .. versionchanged:: 2.0
        The current directory is not changed to the location of the
        loaded file.

    .. versionchanged:: 2.0
        When loading the env files, set the default encoding to UTF-8.

    .. versionchanged:: 1.1.0
        Returns ``False`` when python-dotenv is not installed, or when
        the given path isn't a file.

    .. versionadded:: 1.0
    """
    try:
        import dotenv
    except ImportError:
        if path or os.path.isfile(".env") or os.path.isfile(".flaskenv"):
            click.secho(
                " * Tip: There are .env or .flaskenv files present."
                " Do \"pip install python-dotenv\" to use them.",
                fg="yellow",
                err=True,
            )
        return False

    if path is not None:
        if os.path.isfile(path):
            return dotenv.load_dotenv(path, encoding="utf-8")
        return False

    new_dir = None

    for name in (".env", ".flaskenv"):
        path = dotenv.find_dotenv(name, usecwd=True)

        if not path:
            continue

        if new_dir is None:
            new_dir = os.path.dirname(path)

        dotenv.load_dotenv(path, encoding="utf-8")

    return new_dir is not None

def show_server_banner(debug: bool, app_import_path: str | None) -> None:
    """Show extra startup messages the first time the server is run,
    ignoring the reloader.
    """
    if is_running_from_reloader():
        return

    if app_import_path is not None:
        message = f" * Serving Flask app '{app_import_path}'"

        if debug is not None:
            message += f" (debug={debug})"

        click.echo(message)

    click.echo(" * Environment: " + click.style(os.environ.get("FLASK_ENV", "production"), fg="yellow"))
    click.echo(f" * Debug mode: {debug}")

class CertParamType(click.ParamType):
    """Click option type for the ``--cert`` option. Allows either an
    existing file, the string ``'adhoc'``, or an import for a
    :class:`~ssl.SSLContext` object.
    """
    name = 'path'

    def __init__(self) -> None:
        self.path_type = click.Path(exists=True, dir_okay=False, resolve_path=True)

def _validate_key(ctx: click.Context, param: click.Parameter, value: t.Any) -> t.Any:
    """The ``--key`` option must be specified when ``--cert`` is a file.
    Modifies the ``cert`` param to be a ``(cert, key)`` pair if needed.
    """
    cert = ctx.params.get("cert")
    is_adhoc = cert == "adhoc"

    if value is not None:
        if is_adhoc:
            raise click.BadParameter(
                "When '--cert' is 'adhoc', '--key' is not used.", ctx, param
            )

        if cert is None:
            raise click.BadParameter(
                "'--cert' must also be specified.", ctx, param
            )

        if not os.path.exists(value):
            raise click.BadParameter(
                f"Path '{value}' does not exist.", ctx, param
            )

        ctx.params["cert"] = cert, value

    return value

class SeparatedPathType(click.Path):
    """Click option type that accepts a list of values separated by the
    OS's path separator (``:``, ``;`` on Windows). Each value is
    validated as a :class:`click.Path` type.
    """

@click.command('run', short_help='Run a development server.')
@click.option('--host', '-h', default='127.0.0.1', help='The interface to bind to.')
@click.option('--port', '-p', default=5000, help='The port to bind to.')
@click.option('--cert', type=CertParamType(), help='Specify a certificate file to use HTTPS.', is_eager=True)
@click.option('--key', type=click.Path(exists=True, dir_okay=False, resolve_path=True), callback=_validate_key, expose_value=False, help='The key file to use when specifying a certificate.')
@click.option('--reload/--no-reload', default=None, help='Enable or disable the reloader. By default the reloader is active if debug is enabled.')
@click.option('--debugger/--no-debugger', default=None, help='Enable or disable the debugger. By default the debugger is active if debug is enabled.')
@click.option('--with-threads/--without-threads', default=True, help='Enable or disable multithreading.')
@click.option('--extra-files', default=None, type=SeparatedPathType(), help=f'Extra files that trigger a reload on change. Multiple paths are separated by {os.path.pathsep!r}.')
@click.option('--exclude-patterns', default=None, type=SeparatedPathType(), help=f'Files matching these fnmatch patterns will not trigger a reload on change. Multiple patterns are separated by {os.path.pathsep!r}.')
@pass_script_info
def run_command(info: ScriptInfo, host: str, port: int, reload: bool, debugger: bool, with_threads: bool, cert: ssl.SSLContext | tuple[str, str | None] | t.Literal['adhoc'] | None, extra_files: list[str] | None, exclude_patterns: list[str] | None) -> None:
    """Run a local development server.

    This server is for development purposes only. It does not provide
    the stability, security, or performance of production WSGI servers.

    The reloader and debugger are enabled by default with the '--debug'
    option.
    """
    debug = get_debug_flag()

    if reload is None:
        reload = debug

    if debugger is None:
        debugger = debug

    show_server_banner(debug, info.app_import_path)

    app = info.load_app()
    run_simple(
        host,
        port,
        app,
        use_reloader=reload,
        use_debugger=debugger,
        threaded=with_threads,
        ssl_context=cert,
        extra_files=extra_files,
        exclude_patterns=exclude_patterns,
    )
run_command.params.insert(0, _debug_option)

@click.command('shell', short_help='Run a shell in the app context.')
@with_appcontext
def shell_command() -> None:
    """Run an interactive Python shell in the context of a given
    Flask application.  The application will populate the default
    namespace of this shell according to its configuration.

    This is useful for executing small snippets of management code
    without having to manually configure the application.
    """
    import code
    from flask.globals import _app_ctx_stack

    app = _app_ctx_stack.top.app
    banner = f"Python {sys.version} on {sys.platform}\nApp: {app.import_name}\nInstance: {app.instance_path}"

    ctx = {}

    # Support the regular Python interpreter startup script
    startup = os.environ.get("PYTHONSTARTUP")
    if startup and os.path.isfile(startup):
        with open(startup, "r") as f:
            eval(compile(f.read(), startup, "exec"), ctx)

    ctx.update(app.make_shell_context())

    code.interact(banner=banner, local=ctx)

@click.command('routes', short_help='Show the routes for the app.')
@click.option('--sort', '-s', type=click.Choice(('endpoint', 'methods', 'domain', 'rule', 'match')), default='endpoint', help="Method to sort routes by. 'match' is the order that Flask will match routes when dispatching a request.")
@click.option('--all-methods', is_flag=True, help='Show HEAD and OPTIONS methods.')
@with_appcontext
def routes_command(sort: str, all_methods: bool) -> None:
    """Show all registered routes with endpoints and methods."""
    from flask import current_app

    rules = list(current_app.url_map.iter_rules())
    if not rules:
        click.echo("No routes were registered.")
        return

    ignored_methods = set(() if all_methods else ("HEAD", "OPTIONS"))

    if sort in ("endpoint", "rule"):
        rules = sorted(rules, key=attrgetter(sort))
    elif sort == "methods":
        rules = sorted(rules, key=lambda rule: sorted(rule.methods))

    rule_methods = [", ".join(sorted(rule.methods - ignored_methods)) for rule in rules]

    headers = ("Endpoint", "Methods", "Rule")
    widths = (
        max(len(rule.endpoint) for rule in rules),
        max(len(methods) for methods in rule_methods),
        max(len(rule.rule) for rule in rules),
    )
    widths = [max(len(h), w) for h, w in zip(headers, widths)]
    row = "{{0:<{0}}}  {{1:<{1}}}  {{2:<{2}}}".format(*widths)

    click.echo(row.format(*headers).strip())
    click.echo(row.format(*("-" * width for width in widths)))

    for rule, methods in zip(rules, rule_methods):
        click.echo(row.format(rule.endpoint, methods, rule.rule).rstrip())
cli = FlaskGroup(name='flask', help="A general utility script for Flask applications.\n\nAn application to load must be given with the '--app' option,\n'FLASK_APP' environment variable, or with a 'wsgi.py' or 'app.py' file\nin the current directory.\n")
if __name__ == '__main__':
    main()
