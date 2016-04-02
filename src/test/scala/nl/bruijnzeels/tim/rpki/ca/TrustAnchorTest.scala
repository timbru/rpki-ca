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
package nl.bruijnzeels.tim.rpki.ca

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.RpkiTest
import nl.bruijnzeels.tim.rpki.ca.provisioning.MyIdentity
import org.scalatest.{FunSuite, Matchers}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorTest extends FunSuite with Matchers {

import TrustAnchorTest._

  test("Should create CA and use as TA with self-signed signer and provisioning communicator") {

    val create = CertificateAuthorityCreateAsTrustAnchor(
       aggregateId = TrustAnchorId,
       name = TrustAnchorName,
       resources = TrustAnchorResources,
       certificateUrl = TrustAnchorCertUri,
       baseUrl = TrustAnchorPubUri,
       rrdpNotifyUrl = RrdpNotifyUrl
    )

    val ta = CertificateAuthorityCreateAsTrustAnchorHandler.handle(create)

    val rc = ta.resourceClasses.get(CertificateAuthority.DefaultResourceClassName).get
    val signingMaterial = rc.currentSigner.signingMaterial
    val certificate = signingMaterial.currentCertificate

    signingMaterial.certificateUri should equal(TrustAnchorCertUri)
    certificate.getResources() should equal(TrustAnchorResources)
    certificate.getRepositoryUri() should equal(TrustAnchorPubUri)
    certificate.getRrdpNotifyUri() should equal(RrdpNotifyUrl)

    ta.communicator should not be (None)
    ta.communicator.me.id should equal(TrustAnchorId)
    ta.communicator.children should have size (0)

    ta should equal(CertificateAuthority.rebuild(ta.events))
  }

  test("Should configure child with parent") {

    val taInitial = TrustAnchorTest.TrustAnchorInitial

    val ca = CertificateAuthorityTest.CertificateAuthorityInitial

    val childIdXml = ca.communicator.me.toChildXml
    val childResources: IpResourceSet = "192.168.0.0/16"

    val addChild = CertificateAuthorityAddChild(versionedId = taInitial.versionedId, childId = ca.versionedId.id, childXml = childIdXml, childResources = childResources)

    val taWithChild = CertificateAuthorityAddChildHandler.handle(addChild, taInitial)

    val parentXml = taWithChild.communicator.getParentXmlForChild(ca.versionedId.id).get
    val addParent = CertificateAuthorityAddParent(ca.versionedId, parentXml)

    val caWithParent = CertificateAuthorityAddParentHandler.handle(addParent, ca)

    val parentKnownByCa = caWithParent.communicator.parent.get
    parentKnownByCa.identityCertificate should equal(taWithChild.communicator.me.identityCertificate)
  }
}

object TrustAnchorTest extends RpkiTest {

  val RrdpNotifyUrl: URI = "http://localhost:8080/rrdp/notify.xml"

  val TrustAnchorId = UUID.fromString("f3ec94ee-ae80-484a-8d58-a1e43bbbddd1")
  val TrustAnchorName = "TA"
  val TrustAnchorCertUri: URI = "rsync://host/ta/ta.cer"
  val TrustAnchorPubUri: URI = "rsync://host/repository/"
  val TrustAnchorResources = IpResourceSet.ALL_PRIVATE_USE_RESOURCES

  val ChildId = UUID.fromString("3a87a4b1-6e22-4a63-ad0f-06f83ad3ca16")
  val ChildIdentity = MyIdentity.create(ChildId)
  val ChildXml = ChildIdentity.toChildXml
  val ChildResources: IpResourceSet = "192.168.0.0/16"

  val TrustAnchorInitial = CertificateAuthorityCreateAsTrustAnchorHandler.handle(CertificateAuthorityCreateAsTrustAnchor(
      aggregateId = TrustAnchorId,
      name = TrustAnchorName,
      resources = TrustAnchorResources,
      certificateUrl = TrustAnchorCertUri,
      baseUrl = TrustAnchorPubUri,
      rrdpNotifyUrl = RrdpNotifyUrl))

}