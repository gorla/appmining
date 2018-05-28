# App mining projects

## Cartographer (MSR 2018)

### Requirements

Cartographer is develolped for Python3.

### Setup
Before running any analysis, you must rename `local_cfg.py.skel` to `local_cfg.py` and updated it with your desired configuration parameters. 

The same must be done for each `luigi.cfg.skel` file inside any Luigi script folder: `apktool`, `backstage`, `flowdroid`, `info_apk`, `libradar`, `soot`, `stringoid`. 

### Sample analysis run
To run one one of Cartographer's analysis, use the following command format:

`python3 <script-name> --apk-list-file <path-to-file-with-list-of-apk-files-to-process> --r <script-option>`

for example: 

`python3 flowdroid_luigi.py --apk-list-file ~/Desktop/list_apks.txt`
