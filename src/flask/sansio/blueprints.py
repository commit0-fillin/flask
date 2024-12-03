from __future__ import annotations
import os
import typing as t
from collections import defaultdict
from functools import update_wrapper
from .. import typing as ft
from .scaffold import _endpoint_from_view_func
from .scaffold import _sentinel
from .scaffold import Scaffold
from .scaffold import setupmethod
if t.TYPE_CHECKING:
    from .app import App
DeferredSetupFunction = t.Callable[['BlueprintSetupState'], None]
T_after_request = t.TypeVar('T_after_request', bound=ft.AfterRequestCallable[t.Any])
T_before_request = t.TypeVar('T_before_request', bound=ft.BeforeRequestCallable)
T_error_handler = t.TypeVar('T_error_handler', bound=ft.ErrorHandlerCallable)
T_teardown = t.TypeVar('T_teardown', bound=ft.TeardownCallable)
T_template_context_processor = t.TypeVar('T_template_context_processor', bound=ft.TemplateContextProcessorCallable)
T_template_filter = t.TypeVar('T_template_filter', bound=ft.TemplateFilterCallable)
T_template_global = t.TypeVar('T_template_global', bound=ft.TemplateGlobalCallable)
T_template_test = t.TypeVar('T_template_test', bound=ft.TemplateTestCallable)
T_url_defaults = t.TypeVar('T_url_defaults', bound=ft.URLDefaultCallable)
T_url_value_preprocessor = t.TypeVar('T_url_value_preprocessor', bound=ft.URLValuePreprocessorCallable)

class BlueprintSetupState:
    """Temporary holder object for registering a blueprint with the
    application.  An instance of this class is created by the
    :meth:`~flask.Blueprint.make_setup_state` method and later passed
    to all register callback functions.
    """

    def __init__(self, blueprint: Blueprint, app: App, options: t.Any, first_registration: bool) -> None:
        self.app = app
        self.blueprint = blueprint
        self.options = options
        self.first_registration = first_registration
        subdomain = self.options.get('subdomain')
        if subdomain is None:
            subdomain = self.blueprint.subdomain
        self.subdomain = subdomain
        url_prefix = self.options.get('url_prefix')
        if url_prefix is None:
            url_prefix = self.blueprint.url_prefix
        self.url_prefix = url_prefix
        self.name = self.options.get('name', blueprint.name)
        self.name_prefix = self.options.get('name_prefix', '')
        self.url_defaults = dict(self.blueprint.url_values_defaults)
        self.url_defaults.update(self.options.get('url_defaults', ()))

    def add_url_rule(self, rule: str, endpoint: str | None=None, view_func: ft.RouteCallable | None=None, **options: t.Any) -> None:
        """A helper method to register a rule (and optionally a view function)
        to the application.  The endpoint is automatically prefixed with the
        blueprint's name.
        """
        pass

class Blueprint(Scaffold):
    """Represents a blueprint, a collection of routes and other
    app-related functions that can be registered on a real application
    later.

    A blueprint is an object that allows defining application functions
    without requiring an application object ahead of time. It uses the
    same decorators as :class:`~flask.Flask`, but defers the need for an
    application by recording them for later registration.

    Decorating a function with a blueprint creates a deferred function
    that is called with :class:`~flask.blueprints.BlueprintSetupState`
    when the blueprint is registered on an application.

    See :doc:`/blueprints` for more information.

    :param name: The name of the blueprint. Will be prepended to each
        endpoint name.
    :param import_name: The name of the blueprint package, usually
        ``__name__``. This helps locate the ``root_path`` for the
        blueprint.
    :param static_folder: A folder with static files that should be
        served by the blueprint's static route. The path is relative to
        the blueprint's root path. Blueprint static files are disabled
        by default.
    :param static_url_path: The url to serve static files from.
        Defaults to ``static_folder``. If the blueprint does not have
        a ``url_prefix``, the app's static route will take precedence,
        and the blueprint's static files won't be accessible.
    :param template_folder: A folder with templates that should be added
        to the app's template search path. The path is relative to the
        blueprint's root path. Blueprint templates are disabled by
        default. Blueprint templates have a lower precedence than those
        in the app's templates folder.
    :param url_prefix: A path to prepend to all of the blueprint's URLs,
        to make them distinct from the rest of the app's routes.
    :param subdomain: A subdomain that blueprint routes will match on by
        default.
    :param url_defaults: A dict of default values that blueprint routes
        will receive by default.
    :param root_path: By default, the blueprint will automatically set
        this based on ``import_name``. In certain situations this
        automatic detection can fail, so the path can be specified
        manually instead.

    .. versionchanged:: 1.1.0
        Blueprints have a ``cli`` group to register nested CLI commands.
        The ``cli_group`` parameter controls the name of the group under
        the ``flask`` command.

    .. versionadded:: 0.7
    """
    _got_registered_once = False

    def __init__(self, name: str, import_name: str, static_folder: str | os.PathLike[str] | None=None, static_url_path: str | None=None, template_folder: str | os.PathLike[str] | None=None, url_prefix: str | None=None, subdomain: str | None=None, url_defaults: dict[str, t.Any] | None=None, root_path: str | None=None, cli_group: str | None=_sentinel):
        super().__init__(import_name=import_name, static_folder=static_folder, static_url_path=static_url_path, template_folder=template_folder, root_path=root_path)
        if not name:
            raise ValueError("'name' may not be empty.")
        if '.' in name:
            raise ValueError("'name' may not contain a dot '.' character.")
        self.name = name
        self.url_prefix = url_prefix
        self.subdomain = subdomain
        self.deferred_functions: list[DeferredSetupFunction] = []
        if url_defaults is None:
            url_defaults = {}
        self.url_values_defaults = url_defaults
        self.cli_group = cli_group
        self._blueprints: list[tuple[Blueprint, dict[str, t.Any]]] = []

    @setupmethod
    def record(self, func: DeferredSetupFunction) -> None:
        """Registers a function that is called when the blueprint is
        registered on the application.  This function is called with the
        state as argument as returned by the :meth:`make_setup_state`
        method.
        """
        self.deferred_functions.append(func)

    @setupmethod
    def record_once(self, func: DeferredSetupFunction) -> None:
        """Works like :meth:`record` but wraps the function in another
        function that will ensure the function is only called once.  If the
        blueprint is registered a second time on the application, the
        function passed is not called.
        """
        def wrapper(state: BlueprintSetupState) -> None:
            if not wrapper.called:
                func(state)
                wrapper.called = True
        wrapper.called = False
        self.record(wrapper)

    def make_setup_state(self, app: App, options: dict[str, t.Any], first_registration: bool=False) -> BlueprintSetupState:
        """Creates an instance of :meth:`~flask.blueprints.BlueprintSetupState`
        object that is later passed to the register callback functions.
        Subclasses can override this to return a subclass of the setup state.
        """
        return BlueprintSetupState(self, app, options, first_registration)

    @setupmethod
    def register_blueprint(self, blueprint: Blueprint, **options: t.Any) -> None:
        """Register a :class:`~flask.Blueprint` on this blueprint. Keyword
        arguments passed to this method will override the defaults set
        on the blueprint.

        .. versionchanged:: 2.0.1
            The ``name`` option can be used to change the (pre-dotted)
            name the blueprint is registered with. This allows the same
            blueprint to be registered multiple times with unique names
            for ``url_for``.

        .. versionadded:: 2.0
        """
        self._blueprints.append((blueprint, options))

    def register(self, app: App, options: dict[str, t.Any]) -> None:
        """Called by :meth:`Flask.register_blueprint` to register all
        views and callbacks registered on the blueprint with the
        application. Creates a :class:`.BlueprintSetupState` and calls
        each :meth:`record` callback with it.

        :param app: The application this blueprint is being registered
            with.
        :param options: Keyword arguments forwarded from
            :meth:`~Flask.register_blueprint`.

        .. versionchanged:: 2.3
            Nested blueprints now correctly apply subdomains.

        .. versionchanged:: 2.1
            Registering the same blueprint with the same name multiple
            times is an error.

        .. versionchanged:: 2.0.1
            Nested blueprints are registered with their dotted name.
            This allows different blueprints with the same name to be
            nested at different locations.

        .. versionchanged:: 2.0.1
            The ``name`` option can be used to change the (pre-dotted)
            name the blueprint is registered with. This allows the same
            blueprint to be registered multiple times with unique names
            for ``url_for``.
        """
        self._got_registered_once = True
        state = self.make_setup_state(app, options)

        if self.name in app.blueprints:
            assert app.blueprints[self.name] is self, (
                f"Blueprint name collision: {self.name!r}. This is "
                f"usually caused by multiple blueprints with the same "
                f"name, or by registering the same blueprint multiple "
                f"times without cleanup."
            )
        else:
            app.blueprints[self.name] = self

        for deferred in self.deferred_functions:
            deferred(state)

        for blueprint, bp_options in self._blueprints:
            blueprint.register(app, {**options, **bp_options})

    @setupmethod
    def add_url_rule(self, rule: str, endpoint: str | None=None, view_func: ft.RouteCallable | None=None, provide_automatic_options: bool | None=None, **options: t.Any) -> None:
        """Register a URL rule with the blueprint. See :meth:`.Flask.add_url_rule` for
        full documentation.

        The URL rule is prefixed with the blueprint's URL prefix. The endpoint name,
        used with :func:`url_for`, is prefixed with the blueprint's name.
        """
        self.record(lambda s: s.add_url_rule(rule, endpoint, view_func, provide_automatic_options, **options))

    @setupmethod
    def app_template_filter(self, name: str | None=None) -> t.Callable[[T_template_filter], T_template_filter]:
        """Register a template filter, available in any template rendered by the
        application. Equivalent to :meth:`.Flask.template_filter`.

        :param name: the optional name of the filter, otherwise the
                     function name will be used.
        """
        def decorator(f: T_template_filter) -> T_template_filter:
            self.add_app_template_filter(f, name=name)
            return f
        return decorator

    @setupmethod
    def add_app_template_filter(self, f: ft.TemplateFilterCallable, name: str | None=None) -> None:
        """Register a template filter, available in any template rendered by the
        application. Works like the :meth:`app_template_filter` decorator. Equivalent to
        :meth:`.Flask.add_template_filter`.

        :param name: the optional name of the filter, otherwise the
                     function name will be used.
        """
        self.record_once(lambda s: s.app.add_template_filter(f, name=name))

    @setupmethod
    def app_template_test(self, name: str | None=None) -> t.Callable[[T_template_test], T_template_test]:
        """Register a template test, available in any template rendered by the
        application. Equivalent to :meth:`.Flask.template_test`.

        .. versionadded:: 0.10

        :param name: the optional name of the test, otherwise the
                     function name will be used.
        """
        def decorator(f: T_template_test) -> T_template_test:
            self.add_app_template_test(f, name=name)
            return f
        return decorator

    @setupmethod
    def add_app_template_test(self, f: ft.TemplateTestCallable, name: str | None=None) -> None:
        """Register a template test, available in any template rendered by the
        application. Works like the :meth:`app_template_test` decorator. Equivalent to
        :meth:`.Flask.add_template_test`.

        .. versionadded:: 0.10

        :param name: the optional name of the test, otherwise the
                     function name will be used.
        """
        self.record_once(lambda s: s.app.add_template_test(f, name=name))

    @setupmethod
    def app_template_global(self, name: str | None=None) -> t.Callable[[T_template_global], T_template_global]:
        """Register a template global, available in any template rendered by the
        application. Equivalent to :meth:`.Flask.template_global`.

        .. versionadded:: 0.10

        :param name: the optional name of the global, otherwise the
                     function name will be used.
        """
        def decorator(f: T_template_global) -> T_template_global:
            self.add_app_template_global(f, name=name)
            return f
        return decorator

    @setupmethod
    def add_app_template_global(self, f: ft.TemplateGlobalCallable, name: str | None=None) -> None:
        """Register a template global, available in any template rendered by the
        application. Works like the :meth:`app_template_global` decorator. Equivalent to
        :meth:`.Flask.add_template_global`.

        .. versionadded:: 0.10

        :param name: the optional name of the global, otherwise the
                     function name will be used.
        """
        self.record_once(lambda s: s.app.add_template_global(f, name=name))

    @setupmethod
    def before_app_request(self, f: T_before_request) -> T_before_request:
        """Like :meth:`before_request`, but before every request, not only those handled
        by the blueprint. Equivalent to :meth:`.Flask.before_request`.
        """
        self.record_once(lambda s: s.app.before_request(f))
        return f

    @setupmethod
    def after_app_request(self, f: T_after_request) -> T_after_request:
        """Like :meth:`after_request`, but after every request, not only those handled
        by the blueprint. Equivalent to :meth:`.Flask.after_request`.
        """
        self.record_once(lambda s: s.app.after_request(f))
        return f

    @setupmethod
    def teardown_app_request(self, f: T_teardown) -> T_teardown:
        """Like :meth:`teardown_request`, but after every request, not only those
        handled by the blueprint. Equivalent to :meth:`.Flask.teardown_request`.
        """
        self.record_once(lambda s: s.app.teardown_request(f))
        return f

    @setupmethod
    def app_context_processor(self, f: T_template_context_processor) -> T_template_context_processor:
        """Like :meth:`context_processor`, but for templates rendered by every view, not
        only by the blueprint. Equivalent to :meth:`.Flask.context_processor`.
        """
        self.record_once(lambda s: s.app.context_processor(f))
        return f

    @setupmethod
    def app_errorhandler(self, code: type[Exception] | int) -> t.Callable[[T_error_handler], T_error_handler]:
        """Like :meth:`errorhandler`, but for every request, not only those handled by
        the blueprint. Equivalent to :meth:`.Flask.errorhandler`.
        """
        def decorator(f: T_error_handler) -> T_error_handler:
            self.record_once(lambda s: s.app.errorhandler(code)(f))
            return f
        return decorator

    @setupmethod
    def app_url_value_preprocessor(self, f: T_url_value_preprocessor) -> T_url_value_preprocessor:
        """Like :meth:`url_value_preprocessor`, but for every request, not only those
        handled by the blueprint. Equivalent to :meth:`.Flask.url_value_preprocessor`.
        """
        self.record_once(lambda s: s.app.url_value_preprocessor(f))
        return f

    @setupmethod
    def app_url_defaults(self, f: T_url_defaults) -> T_url_defaults:
        """Like :meth:`url_defaults`, but for every request, not only those handled by
        the blueprint. Equivalent to :meth:`.Flask.url_defaults`.
        """
        self.record_once(lambda s: s.app.url_defaults(f))
        return f
