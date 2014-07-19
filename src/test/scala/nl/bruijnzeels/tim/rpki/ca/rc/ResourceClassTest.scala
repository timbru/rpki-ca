package nl.bruijnzeels.tim
package rpki
package ca
package rc

import java.net.URI
import java.util.UUID
import org.scalatest.FunSuite
import org.scalatest.Matchers
import javax.security.auth.x500.X500Principal
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildCreated

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ResourceClassTest extends FunSuite with Matchers {

  import ResourceClassTest._

  test("Should created resource class") {
    RcWithSelfSignedSigner.children should have size (0)
    RcWithSelfSignedSigner.resourceClassName should equal(ResourceClassName)
    RcWithSelfSignedSigner.currentSigner should equal(SelfSignedSigner)
  }

  test("Should add child") {
    RcWithSelfSignedSigner.addChild(ChildId, ChildResources) match {
      case Left(createEvent) => {
        createEvent.aggregateId should equal(RcWithSelfSignedSigner.aggregateId)
        createEvent.childId should equal(ChildId)
        createEvent.entitledResources should equal(ChildResources)
        createEvent.resourceClassName should equal(ResourceClassName)
      }
      case _ => fail("Should have created  child")
    }
   
    
  }
  
  test("Should NOT add child with resources not held") {
    RcWithSelfSignedSigner.addChild(ChildId, "192.168.0.0/16") match {
      case Right(failedEvent) =>
      case _ => fail("Should have refused to create child")
    }
  }

}

object ResourceClassTest {

  val AggregateId = UUID.fromString("3e13717b-da5b-4371-a8c1-45d390fd8dc7")
  val ResourceClassName = "test resource class"

  val SignerName = "test signer"
  val SignerSubject = new X500Principal("CN=" + SignerName)
  val SignerResources: IpResourceSet = "10.0.0.0/8"
  val SignerPublicationDir: URI = "rsync://host/some/dir"
  val SignerCertificateUri: URI = "rsync://host/ta/ta.cer"

  val ChildId = UUID.fromString("b716cfff-a58c-426c-81bf-096ae78abed7")
  val ChildPublicationUri: URI = s"rsync://localhost/${ChildId}/"
  val ChildPublicationMftUri: URI = ChildPublicationUri.resolve("child.mft")
  val ChildKeyPair = KeyPairSupport.createRpkiKeyPair
  val ChildSubject = RpkiObjectNameSupport.deriveSubject(ChildKeyPair.getPublic())
  val ChildResources: IpResourceSet = "10.0.0.0/24"

  val ChildCreatedEvent = ChildCreated(aggregateId = AggregateId, resourceClassName = ResourceClassName, childId = ChildId, entitledResources = ChildResources)

  def createChildPkcs10Request() = new RpkiCaCertificateRequestBuilder()
    .withCaRepositoryUri(ChildPublicationUri)
    .withManifestUri(ChildPublicationMftUri)
    .withSubject(ChildSubject)
    .build(ChildKeyPair)

  val SelfSignedSignerCreatedEvents = Signer.createSelfSigned(AggregateId, ResourceClassName, SignerName, SignerResources, SignerCertificateUri, SignerPublicationDir)

  val SelfSignedSigner = Signer.buildFromEvents(SelfSignedSignerCreatedEvents)

  val RcWithSelfSignedSignerCreatedEvent = ResourceClassCreated(aggregateId = AggregateId, resourceClassName = ResourceClassName, currentSigner = SelfSignedSigner)

  val RcWithSelfSignedSigner = ResourceClass.created(RcWithSelfSignedSignerCreatedEvent)

}