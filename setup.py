#
#    Python firewall helpers (fw-helpers)
#
#    Copyright (C) 2017 Denis Pompilio (jawa) <denis.pompilio@gmail.com>
#
#    This file is part of fw-helpers
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, see <http://www.gnu.org/licenses/>.

import os
from distutils.core import setup

if __name__ == '__main__':
    readme_file = os.path.join(os.path.dirname(__file__), 'README.rst')
    release = "1.0.2"
    setup(
        name="fw-helpers",
        version=".".join(release.split('.')),
        url="https://github.com/outini/fw-helpers",
        author="Denis Pompilio (jawa)",
        author_email="denis.pompilio@gmail.com",
        maintainer="Denis Pompilio (jawa)",
        maintainer_email="denis.pompilio@gmail.com",
        description="Python firewall helpers",
        long_description=open(readme_file).read(),
        license="GPLv2",
        platforms=['UNIX'],
        scripts=['bin/iptables-tracer'],
        packages=['fw_helpers'],
        package_dir={'fw_helpers': 'fw_helpers'},
        data_files=[('share/doc/fw_helpers', ['README.rst', 'LICENSE']),
                    ('share/man/man1/', ['man/iptables-tracer.1'])],
        install_requires=['docopt'],
        keywords=['firewall', 'shell', 'helpers', 'iptables'],
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Operating System :: POSIX :: Linux',
            'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
            'Programming Language :: Python',
            'Environment :: Console',
            'Topic :: Utilities',
            'Topic :: System :: Systems Administration',
            ]
        )
