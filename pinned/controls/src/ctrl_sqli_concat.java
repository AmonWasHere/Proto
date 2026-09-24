package controls;

import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

/**
 * SQL injection by string concatenation. The OWASP Benchmark's "sqli" category,
 * reduced to its essentials.
 */
public class ctrl_sqli_concat {

    public void run(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
