from os.path import dirname, abspath, join as pathjoin
from fabric.contrib.project import rsync_project
from fabric.api import *

env.use_ssh_config = True
env.roledefs = {
    'prod': ["img.streamboat.tv"]
}

env.appdir = abspath(dirname(__file__))
env.confdir = pathjoin(env.appdir, "opt/openresty")


def syncconf():
    srcdir = env.confdir + "/"
    dstdir = "/opt/openresty/"
    rsync_project(local_dir=srcdir, remote_dir=dstdir)
    run("systemctl reload openresty.service")
