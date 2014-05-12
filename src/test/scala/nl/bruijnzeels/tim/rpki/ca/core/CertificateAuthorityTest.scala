package nl.bruijnzeels.tim.rpki.ca.core

import org.scalatest.FunSuite
import org.scalatest.Matchers

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CertificateAuthorityTest extends FunSuite with Matchers {
  
  test("Should create Certificate Authority") {
    
    val caName = "test Ca"
    val created = CaCreated(caName)
    val ca = CertificateAuthority.instance(created)
    
    ca.name should equal(caName)
  }

}
