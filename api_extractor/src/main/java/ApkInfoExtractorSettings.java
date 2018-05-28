import com.beust.jcommander.Parameter;

public class ApkInfoExtractorSettings {
    private static final String APKPATH = "-apkPath";
    private static final String PKG_NAME = "-apkName";
    private static final String OUT_FILE = "-out";
    private static final String PACKAGES_FILE = "-packages";
    private static final String API = "-api";
    private static final String PKG = "-pkg";
    private static final String ACTIVITY = "-act";

    @Parameter(names = APKPATH, description = "Path to an apk file", required = true)
    public String apkPath;

    @Parameter(names = PKG_NAME, description = "package name", required = true)
    public String apkName;

    @Parameter(names = OUT_FILE, description = "output file")
    public String output;

    @Parameter(names = PACKAGES_FILE, description = "output file with list of packages")
    public String outputPackages;

    @Parameter(names = API, description = "extract api")
    public boolean do_api = false;

    @Parameter(names = PKG, description = "extract pkg list")
    public boolean do_pkg = false;

    @Parameter(names = ACTIVITY, description = "extract activities")
    public boolean do_activities = false;
}
