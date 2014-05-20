package nl.bruijnzeels.tim.rpki.ca.ta

import  org.scalatest.Matchers
import org.scalatest.FunSuite
import net.ripe.ipresource.IpResourceSet
import java.util.UUID
import java.net.URI

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CreateTaCommandHandlerTest extends FunSuite with Matchers {
  
  test("Should initialise TA with KeyPair and self-signed certificate") {
    
    val id = UUID.fromString("fdff6f65-1d4d-4940-8193-7c71911a2ec5")
    val taUri: URI = "rsync://localhost/ta/root.cer"
    val taResources: IpResourceSet = "10/8"
    
    val createCommand = TaCreate(id, "root", taResources, taUri, "rsync://localhost/ta/pub/")
    
    val createdTa = TaCreateCommandHandler.handle(createCommand)
    
    val events = createdTa.events
    
    events should have size(2)
    events(0) should equal(TaCreated(id, "root"))
    
    val signerCreatedEvent = events(1).asInstanceOf[TaSignerCreated]
    signerCreatedEvent.id should equal(id)
    signerCreatedEvent.signingMaterial.certificateUri should equal(taUri)
    signerCreatedEvent.signingMaterial.currentCertificate.getResources() should equal(taResources)
    
  }

}
