#!/usr/bin/env python3
"""
Setup script for Palo Alto Packet Flow Analysis Tool
"""

from setuptools import setup, find_packages
import os
import sys

# Ensure we're using Python 3.7+
if sys.version_info < (3, 7):
    sys.exit("This package requires Python 3.7 or higher")

# Read the README file
def read_file(filename):
    """Read a file and return its contents."""
    with open(os.path.join(os.path.dirname(__file__), filename), 'r', encoding='utf-8') as f:
        return f.read()

# Get version from the package
def get_version():
    """Get version from package __init__.py"""
    import paloalto_packet_flow
    return paloalto_packet_flow.__version__

# Core requirements (minimal dependencies)
CORE_REQUIREMENTS = [
    'requests>=2.25.0',
    'python-dateutil>=2.8.0',
]

# Optional requirements for enhanced features
OPTIONAL_REQUIREMENTS = {
    'visualization': [
        'matplotlib>=3.3.0',
        'plotly>=5.0.0',
        'networkx>=2.5',
        'seaborn>=0.11.0',
    ],
    'data': [
        'pandas>=1.2.0',
        'PyYAML>=5.4.0',
        'lxml>=4.6.0',
    ],
    'dev': [
        'pytest>=6.0.0',
        'pytest-cov>=2.10.0',
        'black>=21.0.0',
        'flake8>=3.8.0',
        'mypy>=0.800',
    ],
    'docs': [
        'sphinx>=3.5.0',
        'sphinx-rtd-theme>=0.5.0',
    ]
}

# All optional requirements combined
ALL_OPTIONAL = []
for req_list in OPTIONAL_REQUIREMENTS.values():
    ALL_OPTIONAL.extend(req_list)

OPTIONAL_REQUIREMENTS['all'] = ALL_OPTIONAL

setup(
    name='paloalto-packet-flow',
    version=get_version(),
    description='Comprehensive packet flow analysis tool for Palo Alto Networks firewalls',
    long_description=read_file('README.md') if os.path.exists('README.md') else 
                    'A comprehensive tool for analyzing packet flows in Palo Alto Networks firewalls.',
    long_description_content_type='text/markdown',
    author='Palo Alto Packet Flow Analysis Team',
    author_email='support@example.com',
    url='https://github.com/your-org/paloalto-packet-flow',
    project_urls={
        'Documentation': 'https://paloalto-packet-flow.readthedocs.io/',
        'Source': 'https://github.com/your-org/paloalto-packet-flow',
        'Tracker': 'https://github.com/your-org/paloalto-packet-flow/issues',
    },
    packages=find_packages(),
    package_data={
        'paloalto_packet_flow': [
            'requirements.txt',
            'examples/*.py',
            'examples/*.json',
            'templates/*.html',
        ]
    },
    include_package_data=True,
    python_requires='>=3.7',
    install_requires=CORE_REQUIREMENTS,
    extras_require=OPTIONAL_REQUIREMENTS,
    entry_points={
        'console_scripts': [
            'paloalto-flow=paloalto_packet_flow.main:main',
            'pan-flow=paloalto_packet_flow.main:main',
            'flow-analyzer=paloalto_packet_flow.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Systems Administration',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords=[
        'palo alto', 'firewall', 'packet flow', 'network analysis',
        'security', 'monitoring', 'visualization', 'logs', 'traffic analysis'
    ],
    license='MIT',
    zip_safe=False,
    platforms=['any'],
    test_suite='tests',
    tests_require=OPTIONAL_REQUIREMENTS['dev'],
)