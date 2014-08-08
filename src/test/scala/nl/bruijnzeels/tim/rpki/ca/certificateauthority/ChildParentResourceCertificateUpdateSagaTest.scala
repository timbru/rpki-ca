package nl.bruijnzeels.tim.rpki.ca
package certificateauthority

import java.net.URI
import java.util.UUID
import org.scalatest.FunSuite
import org.scalatest.Matchers
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCreate
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import nl.bruijnzeels.tim.rpki.ca.provisioning.MyIdentity
import nl.bruijnzeels.tim.rpki.ca.stringToIpResourceSet
import nl.bruijnzeels.tim.rpki.ca.stringToUri
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCreate
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommand
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityCommandDispatcher
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityCreate
import net.ripe.rpki.commons.provisioning.identity.ChildIdentity
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorAddChild
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityAddParent
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchor

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ChildParentResourceCertificateUpdateSagaTest extends FunSuite with Matchers {

  val TrustAnchorId = UUID.fromString("f3ec94ee-ae80-484a-8d58-a1e43bbbddd1")
  val TrustAnchorName = "TA"
  val TrustAnchorCertUri: URI = "rsync://host/ta/ta.cer"
  val TrustAnchorPubUri: URI = "rsync://host/repository/"
  val TrustAnchorResources = IpResourceSet.ALL_PRIVATE_USE_RESOURCES

  val ChildId = UUID.fromString("3a87a4b1-6e22-4a63-ad0f-06f83ad3ca16")
  val ChildBaseUrl: URI = "rsync://host/repository/"
  val ChildName = "CA"
  val ChildIdentity = MyIdentity.create(ChildId)
  val ChildXml = ChildIdentity.toChildXml
  val ChildResources: IpResourceSet = "192.168.0.0/16"

  test("Child should get certificate from TA") {
    EventStore.clear // Not thread-safe but should not matter here

    val initialTa = TrustAnchorCommandDispatcher.dispatch(
      TrustAnchorCreate(
        id = TrustAnchorId,
        name = TrustAnchorName,
        resources = TrustAnchorResources,
        taCertificateUri = TrustAnchorCertUri,
        publicationUri = TrustAnchorPubUri))

    val initialCa = CertificateAuthorityCommandDispatcher.dispatch(CertificateAuthorityCreate(id = ChildId, name = ChildName, baseUrl = ChildBaseUrl))

    val taWithChild = TrustAnchorCommandDispatcher.dispatch(
      TrustAnchorAddChild(
        id = TrustAnchorId,
        childId = ChildId,
        childXml = initialCa.communicator.me.toChildXml,
        childResources = ChildResources))

    val caWithParent = CertificateAuthorityCommandDispatcher.dispatch(
      CertificateAuthorityAddParent(
        id = ChildId,
        parentXml = taWithChild.communicator.getParentXmlForChild(ChildId).get))

    ChildParentResourceCertificateUpdateSaga.updateCertificates(TrustAnchorId, ChildId)

    val caWithCertificate = CertificateAuthorityCommandDispatcher.load(ChildId).get

    caWithCertificate.resourceClasses should have size (1)
    val caRcWithCertificate = caWithCertificate.resourceClasses.get(TrustAnchor.DefaultResourceClassName).get
    val caCertificate = caRcWithCertificate.currentSigner.signingMaterial.currentCertificate

    caCertificate.getResources() should equal(ChildResources)
  }

}