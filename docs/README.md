# UniFi Controller API Documentation

This directory contains the source files for the UniFi Controller API documentation.

## Building the Documentation

### Prerequisites

Install the documentation dependencies:

```bash
pip install -e ".[docs]"
```

### Build HTML Documentation

On Windows:
```bash
cd docs
.\make.bat html
```

On Linux/macOS:
```bash
cd docs
make html
```

The built documentation will be in the `_build/html` directory. Open `_build/html/index.html` in your browser to view it.

### Clean Build

To clean the build directory:

On Windows:
```bash
cd docs
.\make.bat clean
```

On Linux/macOS:
```bash
cd docs
make clean
```

## Documentation Structure

- `conf.py` - Sphinx configuration
- `index.rst` - Main documentation page
- `*.rst` - ReStructuredText documentation files
- `_templates/` - Custom Sphinx templates
- `_static/` - Static files (CSS, JS, images)
- `_build/` - Generated documentation (not in git)