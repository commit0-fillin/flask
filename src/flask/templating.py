from __future__ import annotations
import typing as t
from jinja2 import BaseLoader
from jinja2 import Environment as BaseEnvironment
from jinja2 import Template
from jinja2 import TemplateNotFound
from .globals import _cv_app
from .globals import _cv_request
from .globals import current_app
from .globals import request
from .helpers import stream_with_context
from .signals import before_render_template
from .signals import template_rendered
if t.TYPE_CHECKING:
    from .app import Flask
    from .sansio.app import App
    from .sansio.scaffold import Scaffold

def _default_template_ctx_processor() -> dict[str, t.Any]:
    """Default template context processor.  Injects `request`,
    `session` and `g`.
    """
    return {
        'request': request,
        'session': session,
        'g': g
    }

class Environment(BaseEnvironment):
    """Works like a regular Jinja2 environment but has some additional
    knowledge of how Flask's blueprint works so that it can prepend the
    name of the blueprint to referenced templates if necessary.
    """

    def __init__(self, app: App, **options: t.Any) -> None:
        if 'loader' not in options:
            options['loader'] = app.create_global_jinja_loader()
        BaseEnvironment.__init__(self, **options)
        self.app = app

class DispatchingJinjaLoader(BaseLoader):
    """A loader that looks for templates in the application and all
    the blueprint folders.
    """

    def __init__(self, app: App) -> None:
        self.app = app

def render_template(template_name_or_list: str | Template | list[str | Template], **context: t.Any) -> str:
    """Render a template by name with the given context.

    :param template_name_or_list: The name of the template to render. If
        a list is given, the first name to exist will be rendered.
    :param context: The variables to make available in the template.
    """
    ctx = _request_ctx_stack.top
    ctx.app.update_template_context(context)
    return ctx.app.jinja_env.get_or_select_template(template_name_or_list).render(context)

def render_template_string(source: str, **context: t.Any) -> str:
    """Render a template from the given source string with the given
    context.

    :param source: The source code of the template to render.
    :param context: The variables to make available in the template.
    """
    ctx = _request_ctx_stack.top
    ctx.app.update_template_context(context)
    return ctx.app.jinja_env.from_string(source).render(context)

def stream_template(template_name_or_list: str | Template | list[str | Template], **context: t.Any) -> t.Iterator[str]:
    """Render a template by name with the given context as a stream.
    This returns an iterator of strings, which can be used as a
    streaming response from a view.

    :param template_name_or_list: The name of the template to render. If
        a list is given, the first name to exist will be rendered.
    :param context: The variables to make available in the template.

    .. versionadded:: 2.2
    """
    ctx = _request_ctx_stack.top
    ctx.app.update_template_context(context)
    template = ctx.app.jinja_env.get_or_select_template(template_name_or_list)
    return template.stream(context)

def stream_template_string(source: str, **context: t.Any) -> t.Iterator[str]:
    """Render a template from the given source string with the given
    context as a stream. This returns an iterator of strings, which can
    be used as a streaming response from a view.

    :param source: The source code of the template to render.
    :param context: The variables to make available in the template.

    .. versionadded:: 2.2
    """
    ctx = _request_ctx_stack.top
    ctx.app.update_template_context(context)
    template = ctx.app.jinja_env.from_string(source)
    return template.stream(context)
