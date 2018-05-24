import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ApkInfoExtractorTest {
    @Test
    public void testGetPackagePrefix() {
        ApkInfoExtractor apkInfoExtractor = new ApkInfoExtractor();
        assertEquals("com.android", apkInfoExtractor.getPackagePrefix("com.android.www.ads"));
        assertEquals("com.android", apkInfoExtractor.getPackagePrefix("com.android.service.www.ads"));
        assertEquals("com.www.ads", apkInfoExtractor.getPackagePrefix("com.www.ads"));
        assertEquals("co.ww.a", apkInfoExtractor.getPackagePrefix("co.ww.a"));
    }

}