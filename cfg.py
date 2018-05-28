# coding=utf-8
import os
import local_cfg

# root folder
root_folder = os.path.dirname(os.path.realpath(__file__))

# evolution_data folder
evo_data_folder = local_cfg.evo_data_folder

# apks
apks_folder = local_cfg.apks_folder
fake_apks_folder = local_cfg.fake_apks_folder
dynamic_analysis_result_folder = local_cfg.dynamic_analysis_result_folder

# flowdroid
flow_run_folder = 'flowdroid/run'
flow_json_folder = 'flowdroid/json'
flow_aggregated_json_folder = 'flowdroid/aggregated_json'
flow_appflow_folder = 'flowdroid/appflow'
flow_appflow_matrix_folder = 'flowdroid/appflow_matrix'
flow_appflow_base_matrix_folder = 'flowdroid/appflow_base_matrix'
flow_appflow_heatmap_folder = 'flowdroid/appflow_heatmap'
flow_ic3_model_folder = 'flowdroid/ic3_model'

# permission
perm_matrix_folder = 'permission/perm_matrix'

# analysis
analysis_flow_folder = 'analysis/flow_analysis'
analysis_flow_heatmap_folder = 'analysis/flow_analysis_heatmap'
analysis_stringoid_folder = 'analysis/stringoid_analysis'
analysis_stringoid_heatmap_folder = 'analysis/stringoid_analysis_heatmap'
analysis_dns_folder = 'analysis/dns_analysis'
analysis_dns_heatmap_folder = 'analysis/dns_analysis_heatmap'

# apktool
apktool_run_folder = 'apktool/run'
apktool_activity_count_folder = 'apktool/activity_count'
apktool_file_diff_folder = 'apktool/file_diff'
apktool_smalilist_folder = 'apktool/smalilist'
apktool_layout_matrix_folder = 'apktool/layout_matrix'
apktool_layout_heatmap_folder = 'apktool/layout_heatmap'
apktool_manifest_matrix_folder = 'apktool/manifest_matrix'
apktool_manifest_heatmap_folder = 'apktool/manifest_heatmap'
apktool_api_folder = 'apktool/apis'
apktool_api_location_folder = 'apktool/apis_location'
apktool_api_diff_folder = 'apktool/apis_diff'
apktool_permission_api_folder = 'apktool/permission_apis'
apktool_ui_folder = 'apktool/ui_run'
apktool_ui_diff_folder = 'apktool/ui_diff'
apktool_ui_matrix_folder = 'apktool/ui_matrix'
apktool_ui_heatmap_folder = 'apktool/ui_heatmap'

# backstage
backstage_run_ui_folder = 'backstage/run_ui'
backstage_run_api_folder = 'backstage/run_api'
backstage_logs_folder = 'backstage/run_logs'

# libradar
libradar_run_folder = 'libradar/run'
libradar_pkglibrary_folder = 'libradar/pkglibrary'
libradar_app_libs_folder = 'libradar/app_libs'
libradar_comparesmali_folder = 'libradar/comparesmali'
libradar_matrix_folder = 'libradar/matrix'
libradar_heatmap_folder = 'libradar/heatmap'

# dynamic
dynamic_bro_analysis_folder = 'dynamic/bro_analysis'
dynamic_domain_diff_folder = 'dynamic/domain_diff'
dynamic_matrix_folder = 'dynamic/dns_matrix'
dynamic_heatmap_folder = 'dynamic/dns_heatmap'
dynamic_covered_activities_folder = 'dynamic/covered_activities'
dynamic_activity_coverage_folder = 'dynamic/activity_coverage'

# info_apk
info_apk_folder = 'info/apk'
info_app_folder = 'info/app'
info_manifest_activities_folder = 'info/manifest_activities'
info_permission_matrix_folder = 'info/permission_matrix'

# stringoid
stringoid_run_folder = 'stringoid/run'
stringoid_parse_folder = 'stringoid/parse'
stringoid_pkgurl_folder = 'stringoid/pkgurl'
stringoid_commondomains_folder = 'stringoid/commondomains'
stringoid_domains_matrix_folder = 'stringoid/domains_matrix'
stringoid_domains_heatmap_folder = 'stringoid/domains_heatmap'
stringoid_matrix_folder = 'stringoid/stringoid_matrix'
stringoid_heatmap_folder = 'stringoid/stringoid_heatmap'

# permission
permission_apk_folder = 'permission/apk'
permission_app_folder = 'permission/app'
permission_autogranted_api_folder = 'permission/autogranted_apis'
permission_flowdroid_run_folder = 'permission/flowdroid_run'
permission_flowdroid_json_folder = 'permission/flowdroid_json'
permission_flowdroid_app_folder = 'permission/flowdroid_app'
permission_flowdroid_src_sink_folder = 'permission/flowdroid_src_sink'
permission_androguard_api_loc_folder = 'permission/androguard_api_loc'
permission_api_evolution_folder = 'permission/api_evolution'
permission_overprivileged_apk_folder = 'permission/op_apk'
permission_overprivileged_app_folder = 'permission/op_app'

# soot
soot_run_folder = "soot/run"
soot_permission_api_folder = "soot/api"
soot_flowdroid_json_folder = "soot/flowdroid_json"
soot_flowdroid_run_folder = "soot/flowdroid_run"
soot_flowdroid_content_folder = "soot/flowdroid_content"
soot_combined_folder = "soot/combined"
soot_pkglist_folder = "soot/pkglist"
soot_smalilist_folder = "soot/smalilist"

# activities
activity_diff_folder = "activities/diff"
activity_hidden_folder = "activities/hidden"
