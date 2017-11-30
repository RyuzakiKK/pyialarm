from setuptools import setup

__version__ = '0.2'

setup(
    name='pyialarm',
    py_modules=["pyialarm"],
    version=__version__,
    description='A simple library to interface with iAlarm systems, built for use with Home-Assistant',
    author='Ludovico de Nittis',
    author_email='aasonykk+pyialarm@gmail.com',
    url='https://github.com/RyuzakiKK/pyialarm',
    download_url='https://github.com/RyuzakiKK/pyialarm',
    license='Apache 2.0',
    classifiers=[
      'Development Status :: 3 - Alpha',
      'Intended Audience :: Developers',
      'Programming Language :: Python :: 3',
    ],
    keywords=['ialarm', 'antifurtocasa365', 'alarm'],
    packages=['pyialarm'],
    include_package_data=True,
    install_requires=['requests', 'beautifulsoup4'],
)
