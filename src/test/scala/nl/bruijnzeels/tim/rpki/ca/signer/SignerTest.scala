package nl.bruijnzeels.tim.rpki
package ca
package signer

import org.scalatest.FunSuite
import java.util.UUID
import net.ripe.ipresource.IpResource
import net.ripe.ipresource.IpResourceSet
import java.net.URI
import org.scalatest.Matchers
import javax.security.auth.x500.X500Principal
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilder
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import java.math.BigInteger

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class SignerTest extends FunSuite with Matchers {

  val AggregateId = UUID.fromString("3e13717b-da5b-4371-a8c1-45d390fd8dc7")
  val SignerName = "test signer"
  val SignerSubject = new X500Principal("CN=" + SignerName)
  val SignerResources: IpResourceSet = "10/8"
  val SignerPublicationDir: URI = "rsync://host/some/dir"
  val SignerCertificateUri: URI = "rsync://host/ta/ta.cer"

  val ChildId = UUID.fromString("b716cfff-a58c-426c-81bf-096ae78abed7")
  val ChildPublicationUri: URI = s"rsync://localhost/${ChildId}/"
  val ChildPublicationMftUri: URI = ChildPublicationUri.resolve("child.mft")
  val ChildKeyPair = KeyPairSupport.createRpkiKeyPair
  val ChildSubject = RpkiObjectNameSupport.deriveSubject(ChildKeyPair.getPublic())

  def createChildPkcs10Request() = new RpkiCaCertificateRequestBuilder()
    .withCaRepositoryUri(ChildPublicationUri)
    .withManifestUri(ChildPublicationMftUri)
    .withSubject(ChildSubject)
    .build(ChildKeyPair)

  val selfSignedSigner = Signer.buildFromEvents(Signer.createSelfSigned(AggregateId, SignerName, SignerResources, SignerCertificateUri, SignerPublicationDir))

  test("should create self-signed signer") {

    val signerCertificate = selfSignedSigner.signingMaterial.currentCertificate

    signerCertificate should not be (null)
    signerCertificate.getResources() should equal(SignerResources)
    signerCertificate.getIssuer() should equal(SignerSubject)
    signerCertificate.getSubject() should equal(SignerSubject)
  }

  test("should sign child certificate request") {
    val signingResponse = selfSignedSigner.signChildCertificateRequest(AggregateId, "10.0.0.0/24", createChildPkcs10Request)

    signingResponse.isLeft should be(true)

    val signedEvent = signingResponse.left.get

    val childCertificate = signedEvent.certificate

    childCertificate.getResources() should equal("10.0.0.0/24": IpResourceSet)
    childCertificate.getIssuer() should equal(SignerSubject)
    childCertificate.getSerialNumber() should equal(BigInteger.valueOf(2))

    val updatedSigner = selfSignedSigner.applyEvent(signedEvent)
    updatedSigner.signingMaterial.lastSerial should equal(childCertificate.getSerialNumber())
    updatedSigner.signingMaterial.revocations should have size (0)
  }

  test("should reject overclaiming child certificate request") {
    val signingResponse = selfSignedSigner.signChildCertificateRequest(AggregateId, "192.168.0.0/24", createChildPkcs10Request)
    signingResponse.isRight should be(true)

    val rejectionEvent = signingResponse.right.get
    rejectionEvent.reason should include("192.168.0.0/24")
  }

}