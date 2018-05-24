import os

jarspath = os.path.join(os.getcwd(), "FLOWDROID")
os.chdir(jarspath)

# java -Xmx4g -cp soot-trunk.jar:soot-infoflow.jar:soot-infoflow-android.jar:slf4j-api-1.7.5.jar:slf4j-simple-1.7.5.jar:axml-2.0.jar soot.jimple.infoflow.android.TestApps.Test "D:\Callbacks_Button1.apk" D:\Tools\AndroidSDK\sdk\platforms

jarpackages = "java -Xmx4g -cp soot-trunk.jar:soot-infoflow.jar:soot-infoflow-android.jar:slf4j-api-1.7.5.jar:slf4j-simple-1.7.5.jar:axml-2.0.jar soot.jimple.infoflow.android.TestApps.Test "
platformspath = r"/home/paolo/Android/Sdk/platforms"
apkpath = r"/data/bai"

outputpath = r"/home/bai/flow_analysis_bai/output"
if not os.path.isdir(outputpath):
    os.mkdir(outputpath)

option1 = " --aliasflowins"
option2 = " --contextinsensitive"


def analyze_all():
    apkfolders = os.listdir(apkpath)
    for apkfolder in apkfolders:
        apkfolderpath = os.path.join(apkpath, apkfolder)
        if os.path.isdir(apkfolderpath):
            outputfolderpath = os.path.join(outputpath, apkfolder)
            if not os.path.isdir(outputfolderpath):
                os.mkdir(outputfolderpath)
            apkfiles = os.listdir(apkfolderpath)
            for apkfile in apkfiles:
                apkfilepath = os.path.join(apkfolderpath, apkfile)
                analyze(apkfilepath)


def analyze(apkfilepath):
    outputfolderpath = os.path.join(outputpath, apkfilepath.split("/")[-2])
    print(outputfolderpath)
    apkfile = apkfilepath.split("/")[-1]
    print(apkfile)
    outputfile = outputfolderpath + "/" + apkfile[:apkfile.rindex("_")] + ".txt"
    errfile = outputfolderpath + "/" + apkfile[:apkfile.rindex("_")] + "err.txt"
    cmd = jarpackages + "\"" + apkfilepath + "\" " + platformspath + option1 + option2 + " > " + outputfile + " 2>> " + errfile
    print(cmd)
    os.system(cmd)


if __name__ == '__main__':
    analyze_all()
