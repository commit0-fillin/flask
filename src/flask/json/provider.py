from __future__ import annotations
import dataclasses
import decimal
import json
import typing as t
import uuid
import weakref
from datetime import date
from werkzeug.http import http_date
if t.TYPE_CHECKING:
    from werkzeug.sansio.response import Response
    from ..sansio.app import App

class JSONProvider:
    """A standard set of JSON operations for an application. Subclasses
    of this can be used to customize JSON behavior or use different
    JSON libraries.

    To implement a provider for a specific library, subclass this base
    class and implement at least :meth:`dumps` and :meth:`loads`. All
    other methods have default implementations.

    To use a different provider, either subclass ``Flask`` and set
    :attr:`~flask.Flask.json_provider_class` to a provider class, or set
    :attr:`app.json <flask.Flask.json>` to an instance of the class.

    :param app: An application instance. This will be stored as a
        :class:`weakref.proxy` on the :attr:`_app` attribute.

    .. versionadded:: 2.2
    """

    def __init__(self, app: App) -> None:
        self._app: App = weakref.proxy(app)

    def dumps(self, obj: t.Any, **kwargs: t.Any) -> str:
        """Serialize data as JSON.

        :param obj: The data to serialize.
        :param kwargs: May be passed to the underlying JSON library.
        """
        return json.dumps(obj, **kwargs)

    def dump(self, obj: t.Any, fp: t.IO[str], **kwargs: t.Any) -> None:
        """Serialize data as JSON and write to a file.

        :param obj: The data to serialize.
        :param fp: A file opened for writing text. Should use the UTF-8
            encoding to be valid JSON.
        :param kwargs: May be passed to the underlying JSON library.
        """
        json.dump(obj, fp, **kwargs)

    def loads(self, s: str | bytes, **kwargs: t.Any) -> t.Any:
        """Deserialize data as JSON.

        :param s: Text or UTF-8 bytes.
        :param kwargs: May be passed to the underlying JSON library.
        """
        return json.loads(s, **kwargs)

    def load(self, fp: t.IO[t.AnyStr], **kwargs: t.Any) -> t.Any:
        """Deserialize data as JSON read from a file.

        :param fp: A file opened for reading text or UTF-8 bytes.
        :param kwargs: May be passed to the underlying JSON library.
        """
        return json.load(fp, **kwargs)

    def response(self, *args: t.Any, **kwargs: t.Any) -> Response:
        """Serialize the given arguments as JSON, and return a
        :class:`~flask.Response` object with the ``application/json``
        mimetype.

        The :func:`~flask.json.jsonify` function calls this method for
        the current application.

        Either positional or keyword arguments can be given, not both.
        If no arguments are given, ``None`` is serialized.

        :param args: A single value to serialize, or multiple values to
            treat as a list to serialize.
        :param kwargs: Treat as a dict to serialize.
        """
        from flask import current_app
        from flask.wrappers import Response

        if args and kwargs:
            raise TypeError("Cannot pass both args and kwargs.")
        
        data = args[0] if len(args) == 1 else args if len(args) > 1 else kwargs

        dumped = self.dumps(data)
        return current_app.response_class(dumped, mimetype=self.mimetype)

class DefaultJSONProvider(JSONProvider):
    """Provide JSON operations using Python's built-in :mod:`json`
    library. Serializes the following additional data types:

    -   :class:`datetime.datetime` and :class:`datetime.date` are
        serialized to :rfc:`822` strings. This is the same as the HTTP
        date format.
    -   :class:`uuid.UUID` is serialized to a string.
    -   :class:`dataclasses.dataclass` is passed to
        :func:`dataclasses.asdict`.
    -   :class:`~markupsafe.Markup` (or any object with a ``__html__``
        method) will call the ``__html__`` method to get a string.
    """
    default: t.Callable[[t.Any], t.Any] = staticmethod(_default)
    'Apply this function to any object that :meth:`json.dumps` does\n    not know how to serialize. It should return a valid JSON type or\n    raise a ``TypeError``.\n    '
    ensure_ascii = True
    'Replace non-ASCII characters with escape sequences. This may be\n    more compatible with some clients, but can be disabled for better\n    performance and size.\n    '
    sort_keys = True
    'Sort the keys in any serialized dicts. This may be useful for\n    some caching situations, but can be disabled for better performance.\n    When enabled, keys must all be strings, they are not converted\n    before sorting.\n    '
    compact: bool | None = None
    'If ``True``, or ``None`` out of debug mode, the :meth:`response`\n    output will not add indentation, newlines, or spaces. If ``False``,\n    or ``None`` in debug mode, it will use a non-compact representation.\n    '
    mimetype = 'application/json'
    'The mimetype set in :meth:`response`.'

    def dumps(self, obj: t.Any, **kwargs: t.Any) -> str:
        """Serialize data as JSON to a string.

        Keyword arguments are passed to :func:`json.dumps`. Sets some
        parameter defaults from the :attr:`default`,
        :attr:`ensure_ascii`, and :attr:`sort_keys` attributes.

        :param obj: The data to serialize.
        :param kwargs: Passed to :func:`json.dumps`.
        """
        kwargs.setdefault('default', self.default)
        kwargs.setdefault('ensure_ascii', self.ensure_ascii)
        kwargs.setdefault('sort_keys', self.sort_keys)
        return json.dumps(obj, **kwargs)

    def loads(self, s: str | bytes, **kwargs: t.Any) -> t.Any:
        """Deserialize data as JSON from a string or bytes.

        :param s: Text or UTF-8 bytes.
        :param kwargs: Passed to :func:`json.loads`.
        """
        return json.loads(s, **kwargs)

    def response(self, *args: t.Any, **kwargs: t.Any) -> Response:
        """Serialize the given arguments as JSON, and return a
        :class:`~flask.Response` object with it. The response mimetype
        will be "application/json" and can be changed with
        :attr:`mimetype`.

        If :attr:`compact` is ``False`` or debug mode is enabled, the
        output will be formatted to be easier to read.

        Either positional or keyword arguments can be given, not both.
        If no arguments are given, ``None`` is serialized.

        :param args: A single value to serialize, or multiple values to
            treat as a list to serialize.
        :param kwargs: Treat as a dict to serialize.
        """
        from flask import current_app
        from flask.wrappers import Response

        if args and kwargs:
            raise TypeError("Cannot pass both args and kwargs.")
        
        data = args[0] if len(args) == 1 else args if len(args) > 1 else kwargs or None

        indent = None
        separators = (',', ':')
        if self.compact is False or (self.compact is None and current_app.debug):
            indent = 2
            separators = (', ', ': ')

        dumped = self.dumps(data, indent=indent, separators=separators)
        return current_app.response_class(dumped, mimetype=self.mimetype)
