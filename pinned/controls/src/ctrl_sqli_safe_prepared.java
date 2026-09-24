package controls;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

/**
 * NEGATIVE CONTROL -- this file is not vulnerable.
 *
 * The user value reaches the query only as a bound parameter, which is the
 * documented fix for ctrl_sqli_concat. Its only job is to make a scanner that
 * fires on every `executeQuery` visible as such: without negative controls a
 * matrix of detection rates cannot distinguish a tool that analyses from a tool
 * that pattern-matches the word "query".
 *
 * Expected: no finding. A finding here is a false positive and is counted as
 * one.
 */
public class ctrl_sqli_safe_prepared {

    public void run(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }
}
