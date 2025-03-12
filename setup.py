from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(
    name='scribeauth',
    python_requires='>=3.10.0',
    version='1.2.1',
    description="Library to authenticate to Scribe's platform",
    long_description=readme(),
    url='https://github.com/ScribeLabsAI/ScribeAuth',
    long_description_content_type='text/markdown',
    author='Ailin Venerus',
    author_email='ailin@scribelabs.ai',
    packages=['scribeauth'],
    install_requires=['boto3', 'typing-extensions'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Typing :: Typed'
    ],
)
