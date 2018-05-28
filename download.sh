#! /bin/sh

if [ ! -d "/FLOWDROID" ]; then

  mkdir /FLOWDROID

fi

cd /FLOWDROID

wget http://soot-build.cs.uni-paderborn.de/nightly/soot/soot-trunk.jar
wget https://github.com/secure-software-engineering/soot-infoflow/releases/download/FlowDroid_1.5/soot-infoflow.jar
wget https://github.com/secure-software-engineering/soot-infoflow-android/releases/download/FlowDroid_1.5/soot-infoflow-android.jar
wget https://github.com/secure-software-engineering/soot-infoflow-android/raw/develop/lib/slf4j-api-1.7.5.jar
wget https://github.com/secure-software-engineering/soot-infoflow-android/raw/develop/lib/slf4j-simple-1.7.5.jar
wget https://github.com/secure-software-engineering/soot-infoflow-android/raw/develop/lib/axml-2.0.jar
wget https://github.com/secure-software-engineering/soot-infoflow-android/raw/develop/SourcesAndSinks.txt
wget https://github.com/secure-software-engineering/soot-infoflow/raw/develop/EasyTaintWrapperSource.txt
wget https://github.com/secure-software-engineering/soot-infoflow-android/raw/develop/AndroidCallbacks.txt

