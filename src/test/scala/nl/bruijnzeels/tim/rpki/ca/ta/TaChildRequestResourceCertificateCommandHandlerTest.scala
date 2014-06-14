package nl.bruijnzeels.tim.rpki.ca.ta

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilder

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TaChildRequestResourceCertificateCommandHandlerTest extends TrustAnchorTest {

  def createRequest(resourceClassName: String, ipv4: Option[IpResourceSet] = None) = {
    val pkcs10Request = new RpkiCaCertificateRequestBuilder()
      .withCaRepositoryUri(ChildPublicationUri)
      .withManifestUri(ChildPublicationMftUri)
      .withSubject(ChildSubject)
      .build(ChildKeyPair)

    val request = new CertificateIssuanceRequestPayloadBuilder()
      .withClassName(resourceClassName)
      .withCertificateRequest(pkcs10Request)
      .withIpv4ResourceSet(ipv4.getOrElse(null))
      .build()

    TaChildRequestResourceCertificate(TrustAnchorId, TrustAnchorChildId, request)
  }

  test("Should reject resource request for overclaiming resources") {
    val ChildResourceEntitlement = ResourceEntitlement("private use IP", IpResourceSet.IP_PRIVATE_USE_RESOURCES)
    val command = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List(ChildResourceEntitlement))
    val ta = TaChildSetResourceEntitlementsCommandHandler.handle(command, givenTaWithChild)

    val childCertificateRequest = createRequest(ChildResourceEntitlement.resourceClassName, Some(IpResourceSet.parse("8.0.0.0/8")))

    val taAfterRequest = TaChildRequestResourceCertificateCommandHandler.handle(childCertificateRequest, ta)
    val childAfterRequest = taAfterRequest.children(0)
    childAfterRequest.log should contain("Requesting unentitled resources: 8.0.0.0/8")
  }

  test("Should reject resource request for unknown resource class") {
    val ChildResourceEntitlement = ResourceEntitlement("private use IP", IpResourceSet.IP_PRIVATE_USE_RESOURCES)
    val command = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List(ChildResourceEntitlement))
    val ta = TaChildSetResourceEntitlementsCommandHandler.handle(command, givenTaWithChild)

    val childCertificateRequest = createRequest("my fantasy")

    val taAfterRequest = TaChildRequestResourceCertificateCommandHandler.handle(childCertificateRequest, ta)
    val childAfterRequest = taAfterRequest.children(0)
    childAfterRequest.log should contain("Unknown resource class: my fantasy")
  }

  test("Should honor resource request") {
    val ChildResourceEntitlement = ResourceEntitlement("private use IP", IpResourceSet.IP_PRIVATE_USE_RESOURCES)
    val command = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List(ChildResourceEntitlement))
    val ta = TaChildSetResourceEntitlementsCommandHandler.handle(command, givenTaWithChild)

    val childCertificateRequest = createRequest(ChildResourceEntitlement.resourceClassName)

    val taAfterRequest = TaChildRequestResourceCertificateCommandHandler.handle(childCertificateRequest, ta)
    val childAfterRequest = taAfterRequest.children(0)

    val childKeys = childAfterRequest.resourceClasses.get("private use IP").get.knownKeys
    childKeys should have size (1)
    val childCertificate = childKeys.values.head.currentCertificate
    childCertificate.getResources() should equal(IpResourceSet.IP_PRIVATE_USE_RESOURCES)

    taAfterRequest.signer.get.publicationSet.get.certs.values should contain(childCertificate)
  }

  test("Should sign valid request and only publish the latest certificate for key") {
    val ChildResourceEntitlement = ResourceEntitlement("private use IP", IpResourceSet.IP_PRIVATE_USE_RESOURCES)
    val command = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List(ChildResourceEntitlement))
    val ta = TaChildSetResourceEntitlementsCommandHandler.handle(command, givenTaWithChild)

    val firstChildCertificateRequest = createRequest(ChildResourceEntitlement.resourceClassName)
    val taAfterFirstRequest = TaChildRequestResourceCertificateCommandHandler.handle(firstChildCertificateRequest, ta)
    val childAfterFirstRequest = taAfterFirstRequest.children(0)

    val firstChildCertificate = childAfterFirstRequest.resourceClasses.get("private use IP").get.knownKeys.values.head.currentCertificate
    taAfterFirstRequest.signer.get.publicationSet.get.certs.values should contain(firstChildCertificate)

    val secondChildCertificateRequest = createRequest(ChildResourceEntitlement.resourceClassName)
    val taAfterSecondRequest = TaChildRequestResourceCertificateCommandHandler.handle(secondChildCertificateRequest, taAfterFirstRequest)
    val childAfterSecondRequest = taAfterSecondRequest.children(0)

    val secondChildCertificate = childAfterSecondRequest.resourceClasses.get("private use IP").get.knownKeys.values.head.currentCertificate
    firstChildCertificate should not equal (secondChildCertificate)

    taAfterSecondRequest.signer.get.publicationSet.get.certs.values should not contain (firstChildCertificate)
    taAfterSecondRequest.signer.get.publicationSet.get.certs.values should contain(secondChildCertificate)

  }

}
