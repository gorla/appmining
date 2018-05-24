#!/bin/bash

# checking args
if [[ $# < 1 ]]; then
   echo 'usage: bash openmaps.sh pkgname'
   exit 1
fi

# read pkg name from input
pkg=$1

# setup heatmap directories
flowdroid_heatmap_dir=data/flowdroid_heatmap
apktool_heatmap_dir=data/apktool_heatmap
dns_heatmap_dir=dynamic_analysis/data/dns_heatmap
libradar_heatmap_dir=libradar/data/heatmap
stringoid_heatmap_dir=stingoid/data/heatmap

# create an array containing all directories
dirs=($apktool_heatmap_dir $dns_heatmap_dir $libradar_heatmap_dir)

# open the heatmap in each directory
for d in ${dirs[*]}; do
    echo $d
    open $d/$pkg/$pkg.pdf
done
         


