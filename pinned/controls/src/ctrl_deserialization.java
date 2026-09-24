package controls;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

/**
 * Unsafe deserialization of untrusted data (CWE-502).
 *
 * `ObjectInputStream.readObject` on attacker-controlled bytes is a remote code
 * execution primitive whenever a gadget chain is reachable on the classpath --
 * the mechanism behind the WebLogic and Jenkins deserialization RCEs.
 */
public class ctrl_deserialization {

    public Object run(HttpServletRequest request) throws Exception {
        byte[] data = request.getParameter("data").getBytes("ISO-8859-1");
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
