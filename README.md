# appmining

In order to download android jar files from another repository inside the android/ folder, run the following command (download size ~300GB):
git submodule update --init

Before running the scripts, the local_cfg.py.skel must be renamed to local_cfg.py, and updated with missing local configuration. The same must be done for the luigi.cfg.skel file inside each of the Luigi script folders.
The Luigi scripts are contained inside the following folders: apktool, backstage, flowdroid, info_apk, libradar, soot, stringoid. The --r option is only used in some of the scripts 

The Luigi scripts are developed for python3. To run one of the python script, use the following command:

python3 <script-name> --apk-list-file <path-to-file-with-list-of-apk-files-to-process> --r <script-option>
for example: python3 flowdroid_luigi.py --apk-list-file ~/Desktop/list_apks.txt