package nl.bruijnzeels.tim.rpki.ca.provisioning

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.util.UUID
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.identity.ParentIdentitySerializer
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ProvisioningCommunicatorTest extends FunSuite with Matchers {

  test("Should create provisioning communicator") {
    val id = UUID.randomUUID()
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(id).myIdentity)
    
    pc.me.id should equal (id)
  }
  
  test("Should create parent xml") {
    val childId = MyIdentity.create(UUID.randomUUID)
    val childXml = childId.toChildXml
    
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val parentXml = pc.applyEvent(pc.addChild(childId.id, childXml)).getParentXmlForChild(childId.id)
    
    val parentId = new ParentIdentitySerializer().deserialize(parentXml.get)
    
    parentId.getChildHandle() should equal(childId.id.toString)
    parentId.getChildIdCertificate() should equal(childId.identityCertificate)

    parentId.getParentHandle() should equal(pc.me.id.toString)
    parentId.getParentIdCertificate() should equal(pc.me.identityCertificate)
  }
  
  test("Should add parent, and sign requests to parent with proper sender and recipient..") {
    val childPc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val childXml = childPc.me.toChildXml
    
    val parentPc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val parentXml = parentPc.applyEvent(parentPc.addChild(childPc.me.id, childXml)).getParentXmlForChild(childPc.me.id).get
    
    val childWithParent = childPc.applyEvent(childPc.addParent(parentXml))
    
    childWithParent.parent should equal(Some(ParentIdentity.fromXml(parentXml)))
    
    val requestCms = childWithParent.signRequest(new ResourceClassListQueryPayloadBuilder().build())
    val requestPayload = requestCms.getPayload()
    
    val parentId = new ParentIdentitySerializer().deserialize(parentXml)
    
    requestPayload.getRecipient() should equal(parentId.getParentHandle())
    requestPayload.getSender() should equal(parentId.getChildHandle())
  }
  
}