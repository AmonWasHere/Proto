package controls;

import java.util.Random;

/**
 * Weak randomness used to generate a security token. OWASP Benchmark category
 * "weakrand".
 *
 * `java.util.Random` is a linear congruential generator: observing a few outputs
 * determines the rest. Tokens and reset codes must come from
 * `SecureRandom`/`RandomGenerator` (JDK 17+).
 */
public class ctrl_weakrand_random {

    public String makeToken() {
        Random rnd = new Random();
        return Long.toHexString(rnd.nextLong());
    }
}
