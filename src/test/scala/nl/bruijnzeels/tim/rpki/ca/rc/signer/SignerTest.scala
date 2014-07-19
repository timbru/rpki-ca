package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import org.scalatest.FunSuite
import org.scalatest.Matchers

import common.domain.KeyPairSupport
import common.domain.RpkiObjectNameSupport
import javax.security.auth.x500.X500Principal
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import nl.bruijnzeels.tim.rpki.ca.stringToIpResourceSet
import nl.bruijnzeels.tim.rpki.ca.stringToUri

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class SignerTest extends FunSuite with Matchers {
  
  import ResourceClassTest._
  
  test("should create self-signed signer") {

    val signerCertificate = SelfSignedSigner.signingMaterial.currentCertificate

    signerCertificate should not be (null)
    signerCertificate.getResources() should equal(SignerResources)
    signerCertificate.getIssuer() should equal(SignerSubject)
    signerCertificate.getSubject() should equal(SignerSubject)
  }

  test("should sign child certificate request") {
    val signingResponse = SelfSignedSigner.signChildCertificateRequest(AggregateId, ResourceClassName, "10.0.0.0/24", ChildPkcs10Request)

    signingResponse.isLeft should be(true)

    val signedEvent = signingResponse.left.get

    val childCertificate = signedEvent.certificate

    childCertificate.getResources() should equal("10.0.0.0/24": IpResourceSet)
    childCertificate.getIssuer() should equal(SignerSubject)
    childCertificate.getSerialNumber() should equal(BigInteger.valueOf(2))

    val updatedSigner = SelfSignedSigner.applyEvent(signedEvent)
    updatedSigner.signingMaterial.lastSerial should equal(childCertificate.getSerialNumber())
    updatedSigner.signingMaterial.revocations should have size (0)
  }

  test("should reject overclaiming child certificate request") {
    val signingResponse = SelfSignedSigner.signChildCertificateRequest(AggregateId, ResourceClassName, "192.168.0.0/24", ChildPkcs10Request)
    signingResponse.isRight should be(true)

    val rejectionEvent = signingResponse.right.get
    rejectionEvent.reason should include("192.168.0.0/24")
  }

  test("should publish") {
    SelfSignedSigner.publicationSet.isEmpty should be(true)

    val signerAfterFirstPublish = SelfSignedSigner.applyEvents(SelfSignedSigner.publish(AggregateId, ResourceClassName))

    signerAfterFirstPublish.signingMaterial.lastSerial should equal(BigInteger.valueOf(2)) // Manifest EE certificate should have been signed

    signerAfterFirstPublish.publicationSet.isDefined should be(true)
    val publicationSet = signerAfterFirstPublish.publicationSet.get
    publicationSet.number should equal(BigInteger.ONE)
    publicationSet.crl.getNumber() should equal(BigInteger.ONE)
    publicationSet.mft.getNumber() should equal(BigInteger.ONE)
    publicationSet.products should have size (0)

    signerAfterFirstPublish.revocationList should have size (0)
  }

  test("should RE-publish and revoke old manifest") {
    SelfSignedSigner.publicationSet.isEmpty should be(true)

    val signerAfterFirstPublish = SelfSignedSigner.applyEvents(SelfSignedSigner.publish(AggregateId, ResourceClassName))
    val signerAfterSecondPublish = signerAfterFirstPublish.applyEvents(signerAfterFirstPublish.publish(AggregateId, ResourceClassName))

    signerAfterSecondPublish.signingMaterial.lastSerial should equal(BigInteger.valueOf(3)) // Manifest EE certificate should have been signed

    signerAfterSecondPublish.publicationSet.isDefined should be(true)
    val publicationSet = signerAfterSecondPublish.publicationSet.get
    publicationSet.number should equal(BigInteger.valueOf(2))
    publicationSet.crl.getNumber() should equal(BigInteger.valueOf(2))
    publicationSet.mft.getNumber() should equal(BigInteger.valueOf(2))
    publicationSet.products should have size (0)

    // should revoke mft EE for first publish
    val firstPublishMft = signerAfterFirstPublish.publicationSet.get.mft

    signerAfterSecondPublish.revocationList should have size (1)
    publicationSet.crl.isRevoked(firstPublishMft.getCertificate().getCertificate()) should be(true)
  }

  test("should publish objects") {

    val signingResponse = SelfSignedSigner.signChildCertificateRequest(AggregateId, ResourceClassName, "10.0.0.0/24", ChildPkcs10Request)
    val signedEvent = signingResponse.left.get
    val childCertificate = signedEvent.certificate
    val signerAfterSigning = SelfSignedSigner.applyEvent(signedEvent)

    val signerAfterPublish = signerAfterSigning.applyEvents(signerAfterSigning.publish(AggregateId, ResourceClassName, List(childCertificate)))

    val set = signerAfterPublish.publicationSet.get

    set.mft.getFileNames() should have size (2)
    set.mft.containsFile(RpkiObjectNameSupport.deriveName(childCertificate)) should be(true)
    set.products equals List(childCertificate)
  }

}