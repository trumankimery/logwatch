# setup.py
from setuptools import setup

setup(
    name="logwatch",
    version="0.1.0",
    py_modules=["logwatch"],
    install_requires=["plyer"],
    entry_points={
        "console_scripts": [
            "logwatch = logwatch:main",
        ],
    },
    description="Scan and monitor log files for suspicious activity with optional alerts",
    author="Truman Kimery",
    python_requires=">=3.7",
)