package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorTest
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorAddChild
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorAddChildCommandHandler
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.ipresource.IpResourceSet

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
  
  test("Should configure child with parent") {
    
    val taInitial = TrustAnchorTest.TrustAnchorInitial
    
    val ca = ChildInitial
    
    val childIdXml = new ChildIdentitySerializer().serialize(ca.communicator.me.toChildIdentity)
    val childResources: IpResourceSet = "192.168.0.0/16" 
    val addChild = TrustAnchorAddChild(id = taInitial.id, childId = ca.id, childXml = childIdXml, childResources = childResources)

    val taWithChild = TrustAnchorAddChildCommandHandler.handle(addChild, taInitial)
    
    val parentXml = taWithChild.communicator.getParentXmlForChild(ca.id).get
    val addParent = CertificateAuthorityAddParent(ca.id, parentXml)
    
    val caWithParent = CertificateAuthorityAddParentHandler.handle(addParent, ca)
    
    val parentKnownByCa = caWithParent.communicator.parent.get
    parentKnownByCa.identityCertificate should equal(taWithChild.communicator.me.identityCertificate)
  }

}

object CertificateAuthorityTest {
  
  val CertificateAuthorityId = UUID.fromString("9f750369-6c3d-482a-a9c9-733862778556")
  val CertificateAuthorityName = "Test CA"
    
  val ChildInitial = CertificateAuthorityCreateHandler.handle(CertificateAuthorityCreate(id = CertificateAuthorityId, name = CertificateAuthorityName))
    
  
}