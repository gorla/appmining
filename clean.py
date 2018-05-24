# coding=utf-8
import argparse
import glob
import os
import shutil

import cfg

info_folders = [cfg.info_app_folder, cfg.info_manifest_activities_folder, cfg.info_permission_matrix_folder]
info_folders_hard = [cfg.info_apk_folder]
flow_folders = [cfg.flow_appflow_folder, cfg.flow_appflow_matrix_folder, cfg.flow_appflow_heatmap_folder]
stringoid_folders = [cfg.stringoid_matrix_folder, cfg.stringoid_heatmap_folder]
libradar_folders = [cfg.stringoid_matrix_folder, cfg.stringoid_heatmap_folder]
apktool_folders = [cfg.apktool_layout_heatmap_folder, cfg.apktool_layout_matrix_folder]
flow_folders_hard = [cfg.flow_json_folder, cfg.flow_aggregated_json_folder]

tasks = {'flow': flow_folders, 'lib': libradar_folders, 'apk': apktool_folders, 'url': stringoid_folders,
         'info': info_folders}
tasks_hard = {'flow': flow_folders_hard, 'lib': libradar_folders, 'apk': apktool_folders, 'url': stringoid_folders,
              'info': info_folders_hard}
parser = argparse.ArgumentParser(description='Clean data.')
parser.add_argument("task", choices=tasks.keys(), action='store')
parser.add_argument("pkg")
parser.add_argument("--hard", action='store_true')
parser.add_argument("--all", action='store_true')
args = parser.parse_args()
if args.hard:
    tasks[args.task] += tasks_hard[args.task]

for d in tasks[args.task]:
    if not args.all:
        d = os.path.join(d, args.pkg)
    for f in glob.glob(d + '*'):
        print(f)
        if os.path.exists(f):
            if os.path.isfile(f):
                os.remove(f)
            else:
                shutil.rmtree(f)
