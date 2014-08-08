package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ta

import java.math.BigInteger
import java.net.URI
import java.util.UUID
import org.scalatest.FunSuite
import org.scalatest.Matchers
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayload
import provisioning.MyIdentity
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorTest extends FunSuite with Matchers {

import TrustAnchorTest._

  test("Should create TA with selfsigned signer and provisioning communicator") {

    val create = TrustAnchorCreate(
      id = TrustAnchorId,
      name = TrustAnchorName,
      resources = TrustAnchorResources,
      taCertificateUri = TrustAnchorCertUri,
      publicationUri = TrustAnchorPubUri,
      rrdpNotifyUrl = RrdpNotifyUrl)

    val ta = TrustAnchorCreateCommandHandler.handle(create)

    val rc = ta.resourceClass
    val signingMaterial = rc.currentSigner.signingMaterial
    val certificate = signingMaterial.currentCertificate

    signingMaterial.certificateUri should equal(TrustAnchorCertUri)
    certificate.getResources() should equal(TrustAnchorResources)
    certificate.getRepositoryUri() should equal(TrustAnchorPubUri)
    certificate.getRrdpNotifyUri() should equal(RrdpNotifyUrl)

    ta.communicator should not be (None)
    ta.communicator.me.id should equal(TrustAnchorId)
    ta.communicator.children should have size (0)

    ta should equal(TrustAnchor.rebuild(ta.events))
  }

  test("Should publish") {
    val ta = TrustAnchorInitial.publish

    // Publishing is tested in more detail elsewhere, here I just want to verify that it's done
    val set = ta.resourceClass.currentSigner.publicationSet
    set.number should equal(BigInteger.ONE)

    ta should equal(TrustAnchor.rebuild(ta.events))
  }

  test("Should add child") {
    val addChild = TrustAnchorAddChild(id = TrustAnchorId, childId = ChildId, childXml = ChildXml, childResources = ChildResources)

    val taWithChild = TrustAnchorAddChildCommandHandler.handle(addChild, TrustAnchorInitial)

    taWithChild.communicator.children.isDefinedAt(ChildId) should be(true)
    taWithChild.resourceClass.children.isDefinedAt(ChildId) should be(true)
  }

  test("Should process child resource class list query") {
    val addChild = TrustAnchorAddChild(id = TrustAnchorId, childId = ChildId, childXml = ChildXml, childResources = ChildResources)
    val taWithChild = TrustAnchorAddChildCommandHandler.handle(addChild, TrustAnchorInitial)

    val request = SigningSupport.createProvisioningCms(
      sender = ChildId.toString,
      recipient = TrustAnchorId.toString,
      signingCertificate = ChildIdentity.identityCertificate,
      signingKeyPair = ChildIdentity.keyPair,
      payload = new ResourceClassListQueryPayloadBuilder().build())

    val command = TrustAnchorProcessResourceListQuery(TrustAnchorId, ChildId, request)

    val taAfterResponse = TrustAnchorProcessResourceListQueryCommandHandler.handle(command, taWithChild)

    val exchange = taAfterResponse.communicator.getExchangesForChild(ChildId)(0)

    val responsePayload = exchange.response.getPayload().asInstanceOf[ResourceClassListResponsePayload]
    responsePayload.getSender should equal (TrustAnchorId.toString())
    responsePayload.getRecipient should equal (ChildId.toString())

    val resourceClassInResponse = responsePayload.getClassElements().get(0)
    resourceClassInResponse.getCertificateElements() should be (null)
    resourceClassInResponse.getClassName() should equal (TrustAnchor.DefaultResourceClassName)
    resourceClassInResponse.getResourceSetIpv4() should equal (ChildResources)
    resourceClassInResponse.getResourceSetIpv6() should equal(new IpResourceSet())
    resourceClassInResponse.getResourceSetAsn() should equal(new IpResourceSet())
  }

  test("Should publish TAL with http URI") {
    val tal = TrustAnchorInitial.tal

    tal should startWith ("http://")
  }

}

object TrustAnchorTest {

  val RrdpNotifyUrl: URI = "rrdp://localhost:8080/rrdp/notify.xml"

  val TrustAnchorId = UUID.fromString("f3ec94ee-ae80-484a-8d58-a1e43bbbddd1")
  val TrustAnchorName = "TA"
  val TrustAnchorCertUri: URI = "http://host/ta/ta.cer"
  val TrustAnchorPubUri: URI = "rsync://host/repository/"
  val TrustAnchorResources = IpResourceSet.ALL_PRIVATE_USE_RESOURCES

  val ChildId = UUID.fromString("3a87a4b1-6e22-4a63-ad0f-06f83ad3ca16")
  val ChildIdentity = MyIdentity.create(ChildId)
  val ChildXml = ChildIdentity.toChildXml
  val ChildResources: IpResourceSet = "192.168.0.0/16"

  val TrustAnchorInitial =
    TrustAnchorCreateCommandHandler.handle(
      TrustAnchorCreate(
        id = TrustAnchorId,
        name = TrustAnchorName,
        resources = TrustAnchorResources,
        taCertificateUri = TrustAnchorCertUri,
        publicationUri = TrustAnchorPubUri,
        rrdpNotifyUrl = RrdpNotifyUrl))

}