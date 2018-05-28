#!/bin/bash
# check that luigid is in your path, with pip --user it should be in ~/.local/bin on Linux machine and /Users/<user>/Library/Python/##/bin/ on OSX
luigid --background --pidfile ./pid.file --logdir ./logs --state-path ./luigi-state.pickle

