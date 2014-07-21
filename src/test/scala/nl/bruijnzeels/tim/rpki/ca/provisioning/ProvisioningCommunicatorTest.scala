package nl.bruijnzeels.tim.rpki.ca.provisioning

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.util.UUID
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.identity.ParentIdentitySerializer

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ProvisioningCommunicatorTest extends FunSuite with Matchers {

  test("Should create provisioning communicator") {
    val id = UUID.randomUUID()
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(id).myIdentity)
    
    pc.me.id should equal (id)
  }
  
  test("Should create parent xml") {
    val childId = MyIdentity.create(UUID.randomUUID)
    val childXml = new ChildIdentitySerializer().serialize(childId.toChildIdentity)
    
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val parentXml = pc.applyEvent(pc.addChild(pc.me.id, childId.id, childXml)).getParentXmlForChild(childId.id)
    
    val parentId = new ParentIdentitySerializer().deserialize(parentXml.get)
    
    parentId.getChildHandle() should equal(childId.id.toString)
    parentId.getChildIdCertificate() should equal(childId.identityCertificate)

    parentId.getParentHandle() should equal(pc.me.id.toString)
    parentId.getParentIdCertificate() should equal(pc.me.identityCertificate)
  }
  
  test("Should add parent") {
    val childPc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val childXml = new ChildIdentitySerializer().serialize(childPc.me.toChildIdentity)
    
    val parentPc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val parentXml = parentPc.applyEvent(parentPc.addChild(parentPc.me.id, childPc.me.id, childXml)).getParentXmlForChild(childPc.me.id).get
    
    val childWithParent = childPc.applyEvent(childPc.addParent(childPc.me.id, parentXml))
    
    childWithParent.parent should equal(Some(ParentIdentity.fromXml(parentXml)))
  }
  
}