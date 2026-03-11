"""setup.py — allows `pip install -e .` and `wifitool` console script."""

from setuptools import setup, find_packages

setup(
    name="wifitool",
    version="1.0.0",
    description="Educational Wi-Fi Security Analysis Suite",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["rich>=13.0.0"],
    entry_points={
        "console_scripts": [
            "wifitool=wifi_tool.ui.app:run",
        ],
    },
)
