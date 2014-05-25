package nl.bruijnzeels.tim.rpki.ca.common.domain

import org.scalatest.FunSuite
import org.scalatest.Matchers
import java.security.interfaces.RSAPrivateKey

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class KeyPairSupportTest extends FunSuite with Matchers {

  test("should standard keys RSA and 2048 bits") {
    val kp = KeyPairSupport.createRpkiKeyPair
    val privateKey = kp.getPrivate().asInstanceOf[RSAPrivateKey]

    privateKey.getModulus().bitLength() should equal(2048)
  }

}