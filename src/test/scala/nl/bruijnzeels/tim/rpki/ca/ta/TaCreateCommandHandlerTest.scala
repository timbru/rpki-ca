package nl.bruijnzeels.tim.rpki.ca
package ta

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.signer.SignerCreated
import nl.bruijnzeels.tim.rpki.ca.signer.SignerSignedCertificate

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TaCreateCommandHandlerTest extends TrustAnchorTest {

  test("Should initialise TA with KeyPair and self-signed certificate") {

    val aggregateID = UUID.fromString("fdff6f65-1d4d-4940-8193-7c71911a2ec5")
    val taUri: URI = "rsync://localhost/ta/root.cer"
    val taResources: IpResourceSet = "10/8"

    val createCommand = TaCreate(aggregateID, "root", taResources, taUri, "rsync://localhost/ta/pub/")

    val createdTa = TaCreateCommandHandler.handle(createCommand)

    val events = createdTa.events

    events should have size (3)
    events(0) should equal(TaCreated(aggregateID, "root"))

    val signerCreatedEvent = events(1).asInstanceOf[SignerCreated]
    signerCreatedEvent.aggregateId should equal(aggregateID)
    signerCreatedEvent.signingMaterial.certificateUri should equal(taUri)
    signerCreatedEvent.signingMaterial.currentCertificate.getResources() should equal(taResources)

    val taCertificateSignedEvent = events(2).asInstanceOf[SignerSignedCertificate]
    taCertificateSignedEvent.certificate should equal(signerCreatedEvent.signingMaterial.currentCertificate)
  }

  test("Should not be allowed to initialise TA twice") {
    val ta = givenInitialisedTa
    val e = intercept[TrustAnchorException] { ta.initialise("10/8", "rsync://localhost/ta/root.cer", "rsync://localhost/ta/pub/") }
    e.getMessage() should equal("Signer already initialised")
  }

}
