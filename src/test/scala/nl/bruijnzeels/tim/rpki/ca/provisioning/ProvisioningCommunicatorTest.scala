package nl.bruijnzeels.tim.rpki.ca.provisioning

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.util.UUID

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ProvisioningCommunicatorTest extends FunSuite with Matchers {

  test("Should create provisioning communicator") {
    val id = UUID.randomUUID()
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(id).myIdentity)
    
    pc.me.id should equal (id)
  }
  
}