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
package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.RpkiTest
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.{TrustAnchorAddChild, TrustAnchorAddChildCommandHandler, TrustAnchorTest}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CertificateAuthorityTest extends RpkiTest {

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

object CertificateAuthorityTest extends RpkiTest {

  val RrdpNotifyUrl: URI = "rrdp://localhost:8080/rrdp/notify.xml"

  val CertificateAuthorityId = UUID.fromString("9f750369-6c3d-482a-a9c9-733862778556")
  val CertificateAuthorityName = "Test CA"
  val CertificateAuthorityBaseUrl: URI = "rsync://invalid.com/foo"

  val ChildInitial = CertificateAuthorityCreateHandler.handle(CertificateAuthorityCreate(CertificateAuthorityId, name = CertificateAuthorityName, baseUrl = CertificateAuthorityBaseUrl, rrdpNotifyUrl = RrdpNotifyUrl))

}