package controls;

import java.io.ByteArrayInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * XML external entity injection. OWASP Benchmark category "xxe".
 *
 * No `setFeature` hardening and no external-entity resolver, so the parser is
 * left in its permissive default state -- which is what makes it vulnerable.
 * The safe variant is not written as a paired negative control here because the
 * fix is a three-line feature block rather than a one-word change, and a
 * near-miss negative control would test the rule's tolerance rather than the
 * tool's understanding.
 */
public class ctrl_xxe_documentbuilder {

    public void run(HttpServletRequest request) throws Exception {
        byte[] body = request.getParameter("xml").getBytes("UTF-8");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new ByteArrayInputStream(body));
    }
}
