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
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildCreated
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildReceivedCertificate
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerSignedCertificate
import nl.bruijnzeels.tim.rpki.ca.stringToIpResourceSet
import nl.bruijnzeels.tim.rpki.ca.stringToUri

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

  test("Should sign child request and store certificate") {
    RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request) match {
      case Right(error) => fail("Should sign request")
      case Left(events) => {
        events should have size (2)
        val signed = events(0).asInstanceOf[SignerSignedCertificate]
        val received = events(1).asInstanceOf[ChildReceivedCertificate]
        signed.certificate should equal(received.certificate)
      }
    }
  }

  test("Should publish certificate for child") {
    val rcAfterPublish = RcWithCertifiedChild.applyEvents(RcWithCertifiedChild.publish())
    
    val set = rcAfterPublish.currentSigner.publicationSet
    set.items should have size (3) // mft, crl, cer
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

  val ChildPkcs10Request = new RpkiCaCertificateRequestBuilder()
    .withCaRepositoryUri(ChildPublicationUri)
    .withManifestUri(ChildPublicationMftUri)
    .withSubject(ChildSubject)
    .build(ChildKeyPair)

  val SelfSignedSignerCreatedEvents = Signer.createSelfSigned(AggregateId, ResourceClassName, SignerName, SignerResources, SignerCertificateUri, SignerPublicationDir)

  val SelfSignedSigner = Signer.buildFromEvents(SelfSignedSignerCreatedEvents)

  val RcCreatedEvent = ResourceClassCreated(aggregateId = AggregateId, resourceClassName = ResourceClassName)

  val RcWithSelfSignedSigner = ResourceClass.created(RcCreatedEvent).applyEvents(SelfSignedSignerCreatedEvents)

  val ChildAddedEvent = RcWithSelfSignedSigner.addChild(ChildId, ChildResources).left.get

  val RcWithChild = RcWithSelfSignedSigner.applyEvent(ChildAddedEvent)

  val RcChildSignEvents = RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request).left.get

  val RcWithCertifiedChild = RcWithChild.applyEvents(RcChildSignEvents)

}