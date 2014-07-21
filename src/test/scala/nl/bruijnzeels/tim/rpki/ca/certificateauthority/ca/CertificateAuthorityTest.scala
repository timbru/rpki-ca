package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.util.UUID

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CertificateAuthorityTest extends FunSuite with Matchers {
  
  import CertificateAuthorityTest._
  
  test("Should create certificate authority with initialised provisioning communicator") {
    val create = CertificateAuthorityCreate(id = CertificateAuthorityId, name = CertificateAuthorityName)
    
    val ca = CertificateAuthorityCreateHandler.handle(create)
    
    ca.communicator should not be (null)
    ca.communicator.children should have size(0)
    ca.communicator.me.id should equal(CertificateAuthorityId)
    
    ca should equal(CertificateAuthority.rebuild(ca.events))
  }

}

object CertificateAuthorityTest {
  
  val CertificateAuthorityId = UUID.fromString("9f750369-6c3d-482a-a9c9-733862778556")
  val CertificateAuthorityName = "Test CA"
  
}