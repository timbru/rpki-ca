package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorAddChild
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorAddChildCommandHandler
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorTest
import nl.bruijnzeels.tim.rpki.ca.stringToIpResourceSet
import nl.bruijnzeels.tim.rpki.ca.stringToUri
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CertificateAuthorityTest extends FunSuite with Matchers {

  import CertificateAuthorityTest._

  test("Should create certificate authority with initialised provisioning communicator") {
    val create = CertificateAuthorityCreate(aggregateId = CertificateAuthorityId, name = CertificateAuthorityName, baseUrl = CertificateAuthorityBaseUrl, rrdpNotifyUrl = RrdpNotifyUrl)

    val ca = CertificateAuthorityCreateHandler.handle(create)

    ca.communicator should not be (null)
    ca.communicator.children should have size (0)
    ca.communicator.me.id should equal(CertificateAuthorityId)

    ca should equal(CertificateAuthority.rebuild(ca.events))
  }

  test("Should configure child with parent") {

    val taInitial = TrustAnchorTest.TrustAnchorInitial

    val ca = ChildInitial

    val childIdXml = ca.communicator.me.toChildXml
    val childResources: IpResourceSet = "192.168.0.0/16"
    val addChild = TrustAnchorAddChild(versionedId = taInitial.versionedId, childId = ca.versionedId.id, childXml = childIdXml, childResources = childResources)

    val taWithChild = TrustAnchorAddChildCommandHandler.handle(addChild, taInitial)

    val parentXml = taWithChild.communicator.getParentXmlForChild(ca.versionedId.id).get
    val addParent = CertificateAuthorityAddParent(ca.versionedId, parentXml)

    val caWithParent = CertificateAuthorityAddParentHandler.handle(addParent, ca)

    val parentKnownByCa = caWithParent.communicator.parent.get
    parentKnownByCa.identityCertificate should equal(taWithChild.communicator.me.identityCertificate)
  }

}

object CertificateAuthorityTest {

  val RrdpNotifyUrl: URI = "rrdp://localhost:8080/rrdp/notify.xml"

  val CertificateAuthorityId = UUID.fromString("9f750369-6c3d-482a-a9c9-733862778556")
  val CertificateAuthorityName = "Test CA"
  val CertificateAuthorityBaseUrl: URI = "rsync://invalid.com/foo"

  val ChildInitial = CertificateAuthorityCreateHandler.handle(CertificateAuthorityCreate(CertificateAuthorityId, name = CertificateAuthorityName, baseUrl = CertificateAuthorityBaseUrl, rrdpNotifyUrl = RrdpNotifyUrl))

}