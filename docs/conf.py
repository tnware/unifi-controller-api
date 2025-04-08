import unifi_controller_api
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath('..'))

project = 'unifi-controller-api'
copyright = f'{datetime.now().year}, Tyler Woods'
author = 'Tyler Woods'

release = unifi_controller_api.__version__ if hasattr(
    unifi_controller_api, '__version__') else '0.2.1'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',          # Core Sphinx extension for auto API docs
    'sphinx.ext.autosummary',      # Create summary tables on API doc pages
    'sphinx.ext.viewcode',         # Add links to view source code
    'sphinx.ext.napoleon',         # Support for Google or NumPy style docstrings
    'sphinx.ext.intersphinx',      # Link to other project's documentation
    'sphinx_autodoc_typehints',    # Use type annotations for documentation
]

autosummary_generate = True
autodoc_member_order = 'bysource'
autoclass_content = 'both'
autodoc_typehints = 'description'
autodoc_typehints_format = 'short'
autodoc_inherit_docstrings = True

autosummary_mock_imports = []
autosummary_imported_members = False
autosummary_ignore_module_all = False

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', '_autosummary']


def skip_submodules(app, what, name, obj, skip, options):
    if what == 'module' and name.startswith('unifi_controller_api.models.') and name.count('.') > 2:
        return True
    return skip


def setup(app):
    app.connect('autodoc-skip-member', skip_submodules)


templates_path = ['_templates']
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
html_title = f"{project} Documentation"
html_logo = None

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'requests': ('https://requests.readthedocs.io/en/latest/', None),
}

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_custom_sections = None
