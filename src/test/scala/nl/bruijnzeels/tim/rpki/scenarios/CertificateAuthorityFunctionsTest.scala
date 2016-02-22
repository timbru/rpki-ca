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
package nl.bruijnzeels.tim.rpki.scenarios

import net.ripe.ipresource.{IpRange, Asn}
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import nl.bruijnzeels.tim.rpki.RpkiTest
import nl.bruijnzeels.tim.rpki.app.main.Dsl._
import nl.bruijnzeels.tim.rpki.ca.TrustAnchor
import nl.bruijnzeels.tim.rpki.common.domain.RoaAuthorisation

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CertificateAuthorityFunctionsTest extends RpkiTest {

  import scala.language.postfixOps

  test("Should create Child under TA with certificate") {
    create trustAnchor ()
    create certificateAuthority ChildId
    trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
    certificateAuthority withId ChildId addTa (current trustAnchor)
    certificateAuthority withId ChildId update

    (current certificateAuthority ChildId resourceClasses) should have size (1)
    val caRcWithCertificate = (current certificateAuthority ChildId resourceClasses).get(TrustAnchor.DefaultResourceClassName).get
    val caCertificate = caRcWithCertificate.currentSigner.signingMaterial.currentCertificate

    caCertificate.getResources() should equal(ChildResources)
  }

  test("Should create GrandChild under Child under TA") {
    create trustAnchor ()

    create certificateAuthority ChildId
    trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
    certificateAuthority withId ChildId addTa(current trustAnchor)
    certificateAuthority withId ChildId update

    create certificateAuthority GrandChildId
    certificateAuthority withId ChildId addChild(current certificateAuthority GrandChildId) withResources GrandChildResources
    certificateAuthority withId GrandChildId addParent(current certificateAuthority ChildId)
    certificateAuthority withId GrandChildId update

    (current certificateAuthority GrandChildId resourceClasses) should have size (1)
    val gcRcWithCertificate = (current certificateAuthority GrandChildId resourceClasses).get(TrustAnchor.DefaultResourceClassName).get
    val gcCertificate = gcRcWithCertificate.currentSigner.signingMaterial.currentCertificate

    gcCertificate.getResources() should equal(GrandChildResources)
  }

  test("Create Child with ROA, re-publish, and remove ROA") {
    create trustAnchor ()

    create certificateAuthority ChildId
    def child = certificateAuthority withId ChildId

    trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
    child addTa(current trustAnchor)
    child update

    child addRoaConfig(RoaAuthorisation(asn = "AS1", roaPrefix = "192.168.0.0/24"))

    child publish

    val roas = child listRoas

    roas should have size(1)
    val roa = roas.head
    roa.getAsn should equal ("AS1": Asn)
    roa.getPrefixes should have size (1)
    roa.getPrefixes.get(0).getPrefix should equal ("192.168.0.0/24": IpRange)
    roa.getPrefixes.get(0).getEffectiveMaximumLength should equal (24)

    child publish

    val roasAfterRepubslih = child listRoas

    roasAfterRepubslih should equal (roas)

    child removeRoaConfig(RoaAuthorisation("AS1", "192.168.0.0/24"))
    child publish

    child listRoas() should have size (0)

    val childRevocations = (current certificateAuthority ChildId resourceClasses).map(_._2).map(_.currentSigner).flatMap(_.revocationList)

    childRevocations.exists(_.serial == roa.getCertificate.getSerialNumber) should be (true)
  }


}
