import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import one.util.streamex.EntryStream;
import one.util.streamex.StreamEx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.options.Options;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

/*
Python implementation of java.String.hashCode()
def java_string_hashcode(s):
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000
 */

public class ApkInfoExtractor {
    private static final boolean DEBUG = true;
    private static final Logger logger = LoggerFactory.getLogger("ConstantTracer");
    private static final int OBFUSCATED_ITEM_SIZE = 2;
    private static final int PACKAGE_PREFIX_MIN_SIZE = 8;
    private static final int PACKAGE_PREFIX_MIN_PARTS = 2;
    private static final String OBFUSCATED_TAG = "obfuscated";
    private static final String APPCODE_TAG = "appcode";
    private final List<String> apiClasses = Arrays.asList(
            "com.google.android.",
            "android.",
            "java.io.",
            "java.net.",
            "org.apache.http.");
    private String apkPath;
    private String apkPrefix;
    private Map<String, Integer> refApiTable = new HashMap<>();
    // private Path refTablePath = Paths.get("");

    protected ApkInfoExtractor() {
    }

    public ApkInfoExtractor(String apkName, String apkPath) {
        // try (BufferedReader br = new BufferedReader(new FileReader(config.getExcludeClasses()))) {
        //     while ((line = br.readLine()) != null)
        //         excludeClasses.add(line);
        initialize(apkPath);
        this.apkPath = apkPath;
        apkPrefix = getPackagePrefix(apkName);

    }

    private static Set<String> getActivityDiff(Collection<String> declaredActivities,
                                               Collection<String> codeActivities) {
        Set<String> diff = codeActivities.stream()
                .filter(x -> !declaredActivities.contains(x))
                .collect(Collectors.toSet());
        // Set<SootClass> diffClasses = StreamEx.of(diff)
        //         .map(x -> Scene.v().getSootClass(x))
        //         .toSet();
        return StreamEx.of(diff)
                .map(x -> Scene.v().getSootClass(x))
                .filter(x -> Scene.v().getActiveHierarchy().getSubclassesOf(x).isEmpty()).map(SootClass::getName)
                .toSet();
    }

    private static int getLength(Object o) {
        if (o instanceof CharSequence) {
            return ((CharSequence) o).length();
        }
        return 0;
    }

    private static <T> StreamEx<T> limit(StreamEx<T> input, int size,
                                         int length) {  //FIXME: hard to understand, refactor
        return input.headTail((head, tail) -> size > 1 || length - getLength(head) > 1 ? limit(tail, size - 1,
                length - getLength(head))
                .prepend(head) : Stream.of(head));
    }
    /*
     * from StreamExHeadTailTest.java
     * */
    // public static <T> StreamEx<T> dominators(StreamEx<T> input, BiPredicate<T, T> isDominator) {
    //     return input
    //             .headTail((head, tail) -> dominators(tail.dropWhile(e -> isDominator.test(head, e)), isDominator)
    //                     .prepend(head));
    // }

    public static void main(String[] args) {
        Logger logger = LoggerFactory.getLogger("ApkInfoExtractor");
        ApkInfoExtractorSettings settings = new ApkInfoExtractorSettings();
        JCommander jc = new JCommander(settings);

        try {
            jc.parse(args);
            if (!(settings.do_api || settings.do_pkg || settings.do_activities))
                throw new ParameterException("No action specified, must be -api or -pkg");
            String apkName = settings.apkName;
            ApkInfoExtractor apkInfoExtractor = new ApkInfoExtractor(apkName, settings.apkPath);
            logger.info(String.format("Processing %s", apkName));
            if (settings.do_api) {
                Map<String, List<String>> apis = apkInfoExtractor.getApis();
                apkInfoExtractor.dumpJsonZipped(apis, settings.output);
            }
            if (settings.do_pkg) {
                Collection<String> packageList = apkInfoExtractor.getPackageList();
                apkInfoExtractor.dumpJson(packageList, settings.outputPackages);
            }
            if (settings.do_activities) {
                Collection<String> declaredActivities = apkInfoExtractor.getDeclaredActivities();
                Collection<String> codeActivities = apkInfoExtractor.getActivities();
                Set<String> activityDiff = getActivityDiff(declaredActivities, codeActivities);
                Map<String, Collection<String>> res = new HashMap<>(2);
                res.put("diff", activityDiff);
                res.put("code", codeActivities);
                res.put("manifest", declaredActivities);
                apkInfoExtractor.dumpJson(res, settings.output);
            }
        } catch (ParameterException e) {
            logger.error("ParameterException", e);
            jc.usage();
        } catch (XmlPullParserException e) {
            logger.error("XmlPullParserException", e);
        } catch (IOException e) {
            logger.error("IOException", e);
        }
    }

    String getPackagePrefix(String className) {
        return limit(StreamEx.of(className.split("\\.")), PACKAGE_PREFIX_MIN_PARTS, PACKAGE_PREFIX_MIN_SIZE)
                .joining(".");
    }

    private void dumpJson(Object info, String filePath) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();//
        Path path = Paths.get(filePath);
        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(
                        Files.newOutputStream(path), "UTF-8"))) {
            gson.toJson(info, writer);
        } catch (IOException e) {
            logger.error("Error while building json", e);
        }
    }

    private void dumpJsonZipped(Object info, String filePath) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();//
        Path path = Paths.get(filePath);
        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(new GZIPOutputStream(
                        Files.newOutputStream(path)), "UTF-8"))) {
            gson.toJson(info, writer);
        } catch (IOException e) {
            logger.error("Error while building json", e);
        }
    }

    private Collection<String> getActivities() {
        SootClass androidActivity = Scene.v().getSootClass("android.app.Activity");
        List<String> activities = StreamEx.of(Scene.v().getApplicationClasses())
                .filter(SootClass::isConcrete)
                .filter(x -> Scene.v().getActiveHierarchy().getSuperclassesOf(x).contains(androidActivity))
                .map(SootClass::getName)
                // .filter(x -> x.contains("Activity"))
                .toList();
        return activities;
    }

    /*
     * get shortest common prefixes for locations:
     * @return a mapping (original location -> prefix)
     */
    private Map<String, String> getAggregatedLocations(Collection<String> allLocations) {
        List<String> locations = StreamEx.of(allLocations)
                .sorted()
                .distinct()
                .toList();
        String prefix = locations.get(0);
        Map<String, String> locationRefTable = new HashMap<>();
        for (String s : locations) {
            if (!s.contains(prefix))
                prefix = s;
            locationRefTable.put(s, prefix);
        }
        return locationRefTable;
    }

    private Map<String, List<String>> getApis() {
        // System.out.println("count");
        // long startTime = System.currentTimeMillis();
        //extract api-location pairs
        List<Map.Entry<InvokeExpr, String>> entries = StreamEx.of(Scene.v().getApplicationClasses())
                .filter(sc -> sc.resolvingLevel() == SootClass.BODIES)
                .mapToEntry(SootClass::getMethods, SootClass::getName)
                .flatMapKeys(StreamEx::of)
                .filterKeys(SootMethod::isConcrete)
                .flatMapKeys(m -> StreamEx.of(m.retrieveActiveBody().getUnits()))
                // .parallel()
                .selectKeys(Stmt.class)
                .filterKeys(Stmt::containsInvokeExpr) //get api invocations
                .mapKeys(Stmt::getInvokeExpr)
                .toList();
        // have to split into two streams, otherwise get ConcurrentModificationException
        List<Map.Entry<String, String>> apiPairs = EntryStream.of(entries.stream())
                .mapKeys(InvokeExpr::getMethod)
                .filterKeys(this::isApiClass) //get android apis
                .mapKeys(SootMethod::getSignature)
                .mapValues(this::removeClassName) //strip class name
                .mapValues(this::transformObfuscated) //remove obfuscated suffixes
                .mapValues(this::transformAppCode) // identify app code packages
                .distinct()
                .toList();
        // for (Map.Entry<InvokeExpr, String> entry: apiPairs){
        // }

        List<String> locations = StreamEx.of(apiPairs) // get all api locations
                .map(Map.Entry::getValue).toList();
        Map<String, String> locationRefTable = getAggregatedLocations(
                locations); // keep only the shortest common package names

        Map<String, List<String>> encodedEntries = EntryStream.of(apiPairs.stream())
                // .mapKeys(String::hashCode)
                .mapValues(locationRefTable::get)
                .distinct()
                .grouping();

        // long endTime = System.currentTimeMillis();
        // long totalTime = endTime - startTime;
        // System.out.println(totalTime);
        return encodedEntries;
    }

    private Collection<String> getDeclaredActivities() throws IOException, XmlPullParserException {
        ProcessManifest manifest = new ProcessManifest(apkPath);
        String packageName = manifest.getPackageName();
        List<String> activities = StreamEx.of(manifest.getActivities())
                .flatMapToEntry(AXmlNode::getAttributes)
                .filterKeys("name"::equals)
                .values()
                .map(AXmlAttribute::getValue)
                .select(String.class)
                .map(x -> x.startsWith(".") ? packageName + x : x)
                .map(x -> x.contains(".") ? x : packageName + "." + x)
                .toList();
        // Set<SootClass> entrypoints = new HashSet<>();
        // for (String className : manifest.getEntryPointClasses())
        //     entrypoints.add(Scene.v().getSootClassUnsafe(className));
        return activities;
    }

    private Collection<String> getPackageList() {
        List<String> packages = StreamEx.of(Scene.v().getClasses())
                .map(SootClass::getName)
                .map(this::removeClassName)
                .map(this::transformObfuscated)
                .toList();
        return StreamEx.of(getAggregatedLocations(packages).values()).distinct().toList();
    }

    private void initialize(String apkPath) {
        logger.info("Resetting Soot...");
        G.reset();
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_whole_program(false);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_process_multiple_dex(true);
        // src_prec_apk_class_jimple to use without android sources; src_prec_apk requires android.jar
        // Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
        // Options.v().set_android_jars("/Users/kuznetsov/LAB/workspace/imdea/static_analysis_app/android/");
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_keep_line_number(false);
        Options.v().set_keep_offset(false);
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_no_bodies_for_excluded(true);
        List<String> excludeList = new LinkedList<>();
        excludeList.add("java.*");
        excludeList.add("sun.*");
        excludeList.add("android.*");
        // excludeList.add("com.android.*");
        excludeList.add("com.google.android.*");
        excludeList.add("org.apache.*");
        excludeList.add("org.eclipse.*");
        excludeList.add("soot.*");
        excludeList.add("javax.*");
        Options.v().set_exclude(excludeList);
        List<String> includeList = new LinkedList<>();
        // includeList.add("com.android.support.*");
        // Options.v().set_include(includeList);
        Main.v().autoSetOptions();
        Options.v().set_wrong_staticness(Options.wrong_staticness_fixstrict);
        Scene.v().loadNecessaryClasses();
        // loadRefTable(refTablePath);
    }

    private boolean isApiClass(SootMethod method) {
        //FIXME: sometimes this method causes soot to update getClasses list which leads to ConcurrentModificationException
        String dc = method.getDeclaringClass().getName();
        for (String sc : apiClasses) {
            if (dc.startsWith(sc)) {
                return true;
            }
        }
        return false;
    }

    private void loadRefTable(Path filePath) {
        try (Stream<String> stream = Files.lines(filePath)) {
            stream.forEach(s -> {
                String[] split = s.split(";");
                if (split.length == 2)
                    refApiTable.put(split[1], Integer.valueOf(split[0]));
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String removeClassName(String className) {
        int idx = className.lastIndexOf('.');
        if (idx > 0)
            return className.substring(0, idx);
        else {
            //logger.warn(String.format("Empty package: %s", className));
            return OBFUSCATED_TAG;
        }
    }

    private String transformAppCode(String packageName) {
        String terminatedPackageName = packageName + '.';
        if (terminatedPackageName.startsWith(apkPrefix + '.'))
            return APPCODE_TAG;
        return packageName;
    }

    private String transformObfuscated(String packageName) {
        List<String> reversedPrefix = StreamEx.ofReversed(packageName.split("\\."))
                .dropWhile(s -> s.length() <= OBFUSCATED_ITEM_SIZE).toList();
        String prefix = StreamEx.ofReversed(reversedPrefix).joining(".");
        if (prefix.isEmpty())
            return OBFUSCATED_TAG;
        return prefix;
    }
}