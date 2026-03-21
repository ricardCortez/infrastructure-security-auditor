"""PSI Security Platform + Infrastructure Auditor – unified setup."""
from setuptools import setup, find_packages

setup(
    name="psi-security-platform",
    version="1.0.0",
    description="PSI - Plataforma de Seguridad Integrada with Infrastructure Auditor",
    author="Ricardo Cortez",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=[
        # Auditor
        "click>=8.1.0",
        "jinja2>=3.1.0",
        "anthropic>=0.25.0",
        "pywinrm>=0.4.3",
        "paramiko>=3.4.0",
        "rich>=13.7.0",
        "requests>=2.31.0",
        # PSI API backend
        "fastapi==0.104.1",
        "uvicorn[standard]==0.24.0",
        "pydantic==2.5.0",
        "sqlalchemy==2.0.23",
        "psycopg2-binary==2.9.9",
        "redis==5.0.1",
        "celery==5.3.4",
        "apscheduler==3.10.4",
        "elasticsearch==8.10.0",
        "python-jose[cryptography]==3.3.0",
        "passlib[bcrypt]==1.7.4",
        # Shared
        "pyyaml==6.0.1",
        "tabulate==0.9.0",
        "colorama==0.4.6",
        "prometheus-client==0.19.0",
        "python-dotenv==1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "pytest-timeout>=2.1.0",
            "pytest-asyncio>=0.21.1",
            "flake8>=7.0.0",
            "black>=24.0.0",
            "isort>=5.13.0",
            "mypy>=1.8.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "auditor=src.cli:cli",
            "psi=backend.cli.main:cli",
        ],
    },
)
