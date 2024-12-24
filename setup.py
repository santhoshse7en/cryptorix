"""
A setuptools-based setup module for the Cryptorix package.
For more details, see:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
"""
# -*- encoding: utf-8 -*-
from __future__ import absolute_import, print_function

import setuptools

# Keywords to improve package discoverability on PyPI
keywords = [
    "Hybrid Encryption", "JWE", "KMS", "Secret Manager",
    "Encryption", "Decryption", "AWS", "Security"
]

# Reading long description from README.md
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="Cryptorix",
    version="1.0.3",
    author="M Santhosh Kumar",
    author_email="santhoshse7en@gmail.com",
    description=(
        "A Python package that provides robust encryption and decryption mechanisms, "
        "utilizing JSON Web Encryption (JWE), Hybrid Encryption, AWS KMS, and AWS Secrets Manager. "
        "Ensure the confidentiality and integrity of your data, with secure management of "
        "encryption keys."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=keywords,
    install_requires=[
        "jwcrypto",  # For JSON Web Encryption handling
        "pycryptodome",  # Cryptography toolkit
        "boto3",  # AWS SDK to interact with KMS and Secrets Manager
    ],
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",  # Specify a minimum Python version
    project_urls={  # Additional URLs for the project
        "Documentation": "https://github.com/santhoshse7en/cryptorix#readme",
        "Source": "https://github.com/santhoshse7en/cryptorix",
        "Tracker": "https://github.com/santhoshse7en/cryptorix/issues",
    },
)
