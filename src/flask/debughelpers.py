from __future__ import annotations
import typing as t
from jinja2.loaders import BaseLoader
from werkzeug.routing import RequestRedirect
from .blueprints import Blueprint
from .globals import request_ctx
from .sansio.app import App
if t.TYPE_CHECKING:
    from .sansio.scaffold import Scaffold
    from .wrappers import Request

class UnexpectedUnicodeError(AssertionError, UnicodeError):
    """Raised in places where we want some better error reporting for
    unexpected unicode or binary data.
    """

class DebugFilesKeyError(KeyError, AssertionError):
    """Raised from request.files during debugging.  The idea is that it can
    provide a better error message than just a generic KeyError/BadRequest.
    """

    def __init__(self, request: Request, key: str) -> None:
        form_matches = request.form.getlist(key)
        buf = [f"""You tried to access the file {key!r} in the request.files dictionary but it does not exist. The mimetype for the request is {request.mimetype!r} instead of 'multipart/form-data' which means that no file contents were transmitted. To fix this error you should provide enctype="multipart/form-data" in your form."""]
        if form_matches:
            names = ', '.join((repr(x) for x in form_matches))
            buf.append(f'\n\nThe browser instead transmitted some file names. This was submitted: {names}')
        self.msg = ''.join(buf)

    def __str__(self) -> str:
        return self.msg

class FormDataRoutingRedirect(AssertionError):
    """This exception is raised in debug mode if a routing redirect
    would cause the browser to drop the method or body. This happens
    when method is not GET, HEAD or OPTIONS and the status code is not
    307 or 308.
    """

    def __init__(self, request: Request) -> None:
        exc = request.routing_exception
        assert isinstance(exc, RequestRedirect)
        buf = [f"A request was sent to '{request.url}', but routing issued a redirect to the canonical URL '{exc.new_url}'."]
        if f'{request.base_url}/' == exc.new_url.partition('?')[0]:
            buf.append(' The URL was defined with a trailing slash. Flask will redirect to the URL with a trailing slash if it was accessed without one.')
        buf.append(' Send requests to the canonical URL, or use 307 or 308 for routing redirects. Otherwise, browsers will drop form data.\n\nThis exception is only raised in debug mode.')
        super().__init__(''.join(buf))

def attach_enctype_error_multidict(request: Request) -> None:
    """Patch ``request.files.__getitem__`` to raise a descriptive error
    about ``enctype=multipart/form-data``.

    :param request: The request to patch.
    :meta private:
    """
    orig_getitem = request.files.__getitem__

    def patched_getitem(key):
        try:
            return orig_getitem(key)
        except KeyError:
            raise DebugFilesKeyError(request, key)

    request.files.__getitem__ = patched_getitem

def explain_template_loading_attempts(app: App, template: str, attempts: list[tuple[BaseLoader, Scaffold, tuple[str, str | None, t.Callable[[], bool] | None] | None]]) -> None:
    """This should help developers understand what failed"""
    from .templating import DispatchingJinjaLoader

    info = ['Locating template "%s":' % template]
    total_loader = app.jinja_loader
    if isinstance(total_loader, DispatchingJinjaLoader):
        for idx, (loader, blueprint, triple) in enumerate(attempts):
            if isinstance(triple, tuple):
                name, _filename, _up_to_date = triple
            else:
                name = triple
            if blueprint is not None:
                info.append('  %s. Trying loader of blueprint "%s" (%r)' % (
                    idx + 1, blueprint.name, loader
                ))
            else:
                info.append('  %s. Trying loader of application (%r)' % (
                    idx + 1, loader
                ))
            if triple is None:
                detail = '     - Skipped: no loader returned a triple'
            elif name != template:
                detail = '     - Skipped: found "%s"' % name
            else:
                detail = '     - Found: "%s"' % name
            info.append(detail)
    else:
        info.append('  - Trying loader (%r)' % total_loader)
    app.logger.info('\n'.join(info))
