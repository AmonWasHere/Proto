package controls;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

/**
 * XPath injection. OWASP Benchmark category "xpathi".
 */
public class ctrl_xpathi {

    public void run(HttpServletRequest request) throws Exception {
        String expr = "/users/user[name/text()='" + request.getParameter("name") + "']";
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.evaluate(expr, (Object) null);
    }
}
