# rules/engine/executors/plugins.py
"""Import every executor plugin so the registry is populated. Import for side-effect.

lint.py and run.py both `import executors.plugins` to register all plugins in one
place. When a new executor plugin is added, import it here (the single canonical list).
"""
from . import caldera_command   # noqa: F401
from . import winrm_command     # noqa: F401
from . import smb_write         # noqa: F401
from . import smb_exe_transfer  # noqa: F401
from . import smb_ransom_note   # noqa: F401
from . import smb_rename        # noqa: F401
from . import remote_service    # noqa: F401
from . import remote_schtask    # noqa: F401
from . import psremoting        # noqa: F401
from . import rdp_keystroke     # noqa: F401
from . import hidden_user       # noqa: F401
from . import rare_smb          # noqa: F401
from . import dcomexec          # noqa: F401
from . import wmiexec           # noqa: F401
from . import dcsync            # noqa: F401
from . import ad_reversible     # noqa: F401
from . import ad_directory      # noqa: F401
from . import ad_network        # noqa: F401
from . import kerberos_asreq    # noqa: F401
from . import windows_reversible  # noqa: F401
from . import smb_multipath      # noqa: F401
