import importlib.util
import os

# qtpy defaults to PyQt5, but the tool needs Qt6. Use PyQt6 if it is installed, otherwise PySide6.
# Set QT_API=pyside6 to use PySide6 when both are installed.
if not os.environ.get('QT_API'):
    os.environ['QT_API'] = 'pyqt6' if importlib.util.find_spec('PyQt6') else 'pyside6'
