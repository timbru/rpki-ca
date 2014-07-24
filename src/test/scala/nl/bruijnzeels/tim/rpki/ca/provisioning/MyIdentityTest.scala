package nl.bruijnzeels.tim.rpki.ca.provisioning

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.util.UUID
import javax.security.auth.x500.X500Principal
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class MyIdentityTest extends FunSuite with Matchers {
  
  test("Should create identity") {
    val id = UUID.randomUUID()
    val myIdentity = MyIdentity.create(id)
    
    myIdentity.id should equal(id)
    myIdentity.identityCertificate.getSubject() should equal(new X500Principal("CN=" + id.toString))
    myIdentity.keyPair should not be (null)
  }
  
  test("Should convert to rpki-commons ChildIdentity") {
    val id = UUID.randomUUID()
    val myIdentity = MyIdentity.create(id)
    val childIdentity = new ChildIdentitySerializer().deserialize(myIdentity.toChildXml)
    childIdentity.getIdentityCertificate() should equal (myIdentity.identityCertificate)
    childIdentity.getHandle() should equal (id.toString)
  }

}