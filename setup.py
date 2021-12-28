from setuptools import setup, find_packages

setup(
    name='angrcli',
    version='1.2.0',
    packages=find_packages(exclude=['tests.*', 'tests', 'example.*', 'example']),
    include_package_data=True,
    license='MIT',
    long_description='none',
    python_requires='>=3.6',
    url='https://github.com/fmagin/angr-cli',
    install_requires=['angr', 'Pygments', 'cmd2'],
    package_data={'angrcli': ["py.typed"]},
)
