package controls;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

/**
 * Path traversal. OWASP Benchmark category "pathtraver".
 */
public class ctrl_pathtraver_file {

    private static final String BASE = "/var/www/uploads/";

    public void run(HttpServletRequest request) throws Exception {
        String name = request.getParameter("filename");
        File f = new File(BASE + name);
        f.createNewFile();
    }
}
