package controls;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Reflected cross-site scripting. OWASP Benchmark category "xss".
 *
 * The value is written straight into the response body with no encoding.
 */
public class ctrl_xss_writer {

    public void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + name + "</h1>");
    }
}
