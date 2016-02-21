/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import org.scalatest.{FunSuite, Matchers}

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
    val signingResponse = SelfSignedSigner.signChildCertificateRequest(ResourceClassName, "10.0.0.0/24", ChildPkcs10Request)

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

  test("should include rrdp in SIA of signed certificate") {
    val signingResponse = SelfSignedSigner.signChildCertificateRequest(ResourceClassName, "10.0.0.0/24", ChildPkcs10Request)
    val childCertificate = signingResponse.left.get.certificate

    childCertificate.getRrdpNotifyUri() should equal (RrdpNotifyUri)
  }

  test("should reject overclaiming child certificate request") {
    val signingResponse = SelfSignedSigner.signChildCertificateRequest(ResourceClassName, "192.168.0.0/24", ChildPkcs10Request)
    signingResponse.isRight should be(true)

    val rejectionEvent = signingResponse.right.get
    rejectionEvent.reason should include("192.168.0.0/24")
  }

  test("should publish") {
    SelfSignedSigner.publicationSet.items should have size (0)

    val signerAfterFirstPublish = SelfSignedSigner.applyEvents(SelfSignedSigner.publish(ResourceClassName))

    signerAfterFirstPublish.signingMaterial.lastSerial should equal(BigInteger.valueOf(2)) // Manifest EE certificate should have been signed

    val publicationSet = signerAfterFirstPublish.publicationSet
    publicationSet.number should equal(BigInteger.ONE)
    publicationSet.crl.get.getNumber() should equal(BigInteger.ONE)
    publicationSet.mft.get.getNumber() should equal(BigInteger.ONE)
    publicationSet.items should have size (2)

    signerAfterFirstPublish.revocationList should have size (0)
  }

  test("should RE-publish and revoke old manifest") {
    val signerAfterFirstPublish = SelfSignedSigner.applyEvents(SelfSignedSigner.publish(ResourceClassName))
    val signerAfterSecondPublish = signerAfterFirstPublish.applyEvents(signerAfterFirstPublish.publish(ResourceClassName))

    signerAfterSecondPublish.signingMaterial.lastSerial should equal(BigInteger.valueOf(3)) // Manifest EE certificate should have been signed

    val publicationSet = signerAfterSecondPublish.publicationSet
    publicationSet.number should equal(BigInteger.valueOf(2))
    publicationSet.crl.get.getNumber() should equal(BigInteger.valueOf(2))
    publicationSet.mft.get.getNumber() should equal(BigInteger.valueOf(2))
    publicationSet.items should have size (2)

    // should revoke mft EE for first publish
    val firstPublishMft = signerAfterFirstPublish.publicationSet.mft.get

    signerAfterSecondPublish.revocationList should have size (1)
    publicationSet.crl.get.isRevoked(firstPublishMft.getCertificate().getCertificate()) should be(true)
  }

  test("should publish objects") {

    val signingResponse = SelfSignedSigner.signChildCertificateRequest(ResourceClassName, "10.0.0.0/24", ChildPkcs10Request)
    val signedEvent = signingResponse.left.get
    val childCertificate = signedEvent.certificate
    val signerAfterSigning = SelfSignedSigner.applyEvent(signedEvent)

    val signerAfterPublish = signerAfterSigning.applyEvents(signerAfterSigning.publish(ResourceClassName, List(childCertificate)))

    val set = signerAfterPublish.publicationSet

    set.mft.get.getFileNames() should have size (2)
    set.mft.get.containsFile(RpkiObjectNameSupport.deriveName(childCertificate)) should be(true)
    set.items.values should contain(childCertificate)
  }

}