from setuptools import setup, find_packages
import os

def get_long_description():
    with open(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'README.md'
    ), encoding='utf8') as fp:
        return fp.read()

setup(
        name='passbolt',
        version='1.22',
        description='Passbolt python module',
        long_description=get_long_description(),
        long_description_content_type='text/markdown',
        author='Daniel Lynch',
        author_email='daniel.lynch2016@gmail.com',
        url='https://github.com/daniel-lynch/passbolt',
        license='MIT',
        # package_dir=["src"],
        packages=find_packages(),
        install_requires=["requests", "python-gnupg", "argparse"],
        data_files=[]
    )
