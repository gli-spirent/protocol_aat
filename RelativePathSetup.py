'''This module sets up relative paths for the automated acceptance tests

Copyright (c) 2019 by Spirent Communications Inc.
All Rights Reserved.
'''

import os, sys, json

from idlpath import content_idl_path

def setup_idl_path(root):
    if not os.environ.has_key('IDLPATH'):
        os.environ['IDLPATH'] = os.pathsep.join([os.path.join(root, 'framework', 'idl')] + [os.path.join(root,idlpath) for idlpath in content_idl_path])

if not os.environ.has_key('HAL_TOP_DIR'):
    # Find the top of the development tree (ROOT)
    _dirs = os.path.dirname(os.path.abspath(__file__)).split(os.path.sep)
    for i in range(len(_dirs), 1, -1):
        _path = os.path.sep.join(_dirs[:i])
        if os.access(os.path.join(_path, 'SConstruct'), os.F_OK):
            ROOT = _path
            break
    else:
        raise RuntimeError, "Couldn't locate top of tree"

    pypath = os.path.join(ROOT, 'framework', 'tools', 'pytools')
    pypath += os.pathsep + os.path.join(ROOT, 'framework', 'il', 'common', 'pymodule')
    pypath += os.pathsep + os.path.join(ROOT, 'framework', 'common', 'pymodule')
    pypath += os.pathsep + os.path.join(ROOT, 'framework', 'common', 'pymodule')
    pypath += os.pathsep + os.path.join(os.getcwd(), 'features', 'steps')
    sys.path.append(os.path.join(ROOT, 'framework', 'tools', 'pytools'))
    sys.path.append(os.path.join(ROOT, 'framework', 'il', 'common', 'pymodule'))
    sys.path.append(os.path.join(ROOT, 'framework', 'common', 'pymodule'))
    #print(sys.path)
    if not os.environ.has_key('PYTHONPATH'):
        os.environ['PYTHONPATH'] = pypath
        #print(os.environ)

    setup_idl_path(ROOT)

# CSPLIST is defined in hw_disc.txt in JSON format, you can define any alias for the port, CSP1 and CSP2 is used for a B2B setup
cspfile = os.path.join( os.getcwd(), 'hw_disc.txt' )
#print(cspfile)
if os.path.exists(cspfile):
    cspinfo = ''
    try:
        with open(cspfile, 'r') as fp:
            cspinfo = fp.read()
    except:
        print('Error(s) occured while openning/reading {}'.format(cspfile))
    if cspinfo:
        csplist = json.loads(cspinfo)
        if 'CSPLIST' in csplist:
            #print(csplist['CPSLIST'])
            for portalias, info in csplist['CSPLIST'].items():
                os.environ[str(portalias)] = str(info)