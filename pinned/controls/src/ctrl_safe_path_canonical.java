package controls;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

/**
 * NEGATIVE CONTROL -- this file is not vulnerable.
 *
 * The same `new File(base, name)` shape as ctrl_pathtraver_file, with the
 * containment check that makes it safe: the resolved path is canonicalised and
 * then verified to still live under the base directory, so `../` cannot escape.
 *
 * This is the stricter of the two negative controls, because the dangerous
 * constructor call is still present and only the surrounding check defuses it.
 * A taint-based tool should clear it; a pure sink-pattern rule will not.
 *
 * Expected: no finding.
 */
public class ctrl_safe_path_canonical {

    private static final File BASE = new File("/var/www/uploads/");

    public void run(HttpServletRequest request) throws Exception {
        String name = request.getParameter("filename");
        File f = new File(BASE, name);
        if (!f.getCanonicalPath().startsWith(BASE.getCanonicalPath() + File.separator)) {
            throw new SecurityException("path escapes base directory");
        }
        f.createNewFile();
    }
}
