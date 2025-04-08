============
Contributing
============

We welcome contributions to the UniFi Controller API project! This document outlines the process for contributing.

Development Environment
-----------------------

1. Fork the repository on GitHub
2. Clone your fork locally:

   .. code-block:: bash

       git clone https://github.com/your-username/unifi-controller-api.git
       cd unifi-controller-api

3. Install development dependencies:

   .. code-block:: bash

       pip install -e ".[dev]"

4. Create a branch for your changes:

   .. code-block:: bash

       git checkout -b your-feature-branch

Testing
-------

Run tests with pytest:

.. code-block:: bash

    pytest

For coverage:

.. code-block:: bash

    pytest --cov=unifi_controller_api tests/

Code Style
----------

This project uses ruff for code linting. Run linting with:

.. code-block:: bash

    ruff check .

Documentation
------------

Build the documentation locally to preview your changes:

.. code-block:: bash

    # Install documentation dependencies if needed
    pip install -e ".[docs]"

    # Build docs
    cd docs
    make html

Pull Request Process
--------------------

1. Ensure your code passes all tests
2. Update documentation as needed
3. Add or update tests for new functionality
4. Submit a Pull Request against the main repository
5. Describe your changes in detail

Documentation Standards
----------------------

- Use Google-style docstrings for Python code
- Include type annotations where appropriate
- Document parameters, return values, and exceptions raised
- Provide usage examples for complex functionality

Example docstring format:

.. code-block:: python

    def function_name(param1: type, param2: type) -> return_type:
        """Short description of the function.

        More detailed description if needed.

        Args:
            param1: Description of param1
            param2: Description of param2

        Returns:
            Description of return value

        Raises:
            ExceptionType: When and why this exception is raised

        Example:
            >>> function_name("example", 123)
            "result"
        """
        # Function implementation