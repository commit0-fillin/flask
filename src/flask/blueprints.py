from __future__ import annotations
import os
import typing as t
from datetime import timedelta
from .cli import AppGroup
from .globals import current_app
from .helpers import send_from_directory
from .sansio.blueprints import Blueprint as SansioBlueprint
from .sansio.blueprints import BlueprintSetupState as BlueprintSetupState
from .sansio.scaffold import _sentinel
if t.TYPE_CHECKING:
    from .wrappers import Response

class Blueprint(SansioBlueprint):

    def __init__(self, name: str, import_name: str, static_folder: str | os.PathLike[str] | None=None, static_url_path: str | None=None, template_folder: str | os.PathLike[str] | None=None, url_prefix: str | None=None, subdomain: str | None=None, url_defaults: dict[str, t.Any] | None=None, root_path: str | None=None, cli_group: str | None=_sentinel) -> None:
        super().__init__(name, import_name, static_folder, static_url_path, template_folder, url_prefix, subdomain, url_defaults, root_path, cli_group)
        self.cli = AppGroup()
        self.cli.name = self.name

    def get_send_file_max_age(self, filename: str | None) -> int | None:
        """Used by :func:`send_file` to determine the ``max_age`` cache
        value for a given file path if it wasn't passed.

        By default, this returns :data:`SEND_FILE_MAX_AGE_DEFAULT` from
        the configuration of :data:`~flask.current_app`. This defaults
        to ``None``, which tells the browser to use conditional requests
        instead of a timed cache, which is usually preferable.

        Note this is a duplicate of the same method in the Flask
        class.

        .. versionchanged:: 2.0
            The default configuration is ``None`` instead of 12 hours.

        .. versionadded:: 0.9
        """
        return current_app.config['SEND_FILE_MAX_AGE_DEFAULT']

    def send_static_file(self, filename: str) -> Response:
        """The view function used to serve files from
        :attr:`static_folder`. A route is automatically registered for
        this view at :attr:`static_url_path` if :attr:`static_folder` is
        set.

        Note this is a duplicate of the same method in the Flask
        class.

        .. versionadded:: 0.5

        """
        if not self.has_static_folder:
            raise RuntimeError("No static folder for this blueprint")
        
        # Ensure cache_timeout is an integer or None
        cache_timeout = self.get_send_file_max_age(filename)
        cache_timeout = int(cache_timeout) if cache_timeout is not None else None

        return send_from_directory(
            self.static_folder,
            filename,
            max_age=cache_timeout
        )

    def open_resource(self, resource: str, mode: str='rb') -> t.IO[t.AnyStr]:
        """Open a resource file relative to :attr:`root_path` for
        reading.

        For example, if the file ``schema.sql`` is next to the file
        ``app.py`` where the ``Flask`` app is defined, it can be opened
        with:

        .. code-block:: python

            with app.open_resource("schema.sql") as f:
                conn.executescript(f.read())

        :param resource: Path to the resource relative to
            :attr:`root_path`.
        :param mode: Open the file in this mode. Only reading is
            supported, valid values are "r" (or "rt") and "rb".

        Note this is a duplicate of the same method in the Flask
        class.

        """
        if mode not in ('r', 'rt', 'rb'):
            raise ValueError("Resources can only be opened for reading")
        
        return open(os.path.join(self.root_path, resource), mode)
