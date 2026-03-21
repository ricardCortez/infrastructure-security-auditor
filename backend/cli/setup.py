from setuptools import setup, find_packages

setup(
    name="psi-cli",
    version="1.0.0",
    description="PSI - Plataforma de Seguridad Integrada CLI",
    author="Ricardo Cortez",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "click==8.1.7",
        "requests==2.31.0",
        "pyyaml==6.0.1",
        "tabulate==0.9.0",
        "rich==13.7.0",
        "colorama==0.4.6",
        "python-dotenv==1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "psi=cli.main:cli",
        ],
    },
)
