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

import net.ripe.ipresource.{IpResourceSet, Asn, IpRange}
import nl.bruijnzeels.tim.rpki.RpkiTest
import nl.bruijnzeels.tim.rpki.app.main.Dsl._
import nl.bruijnzeels.tim.rpki.ca.CertificateAuthority
import nl.bruijnzeels.tim.rpki.common.domain.RoaAuthorisation

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CertificateAuthorityChildResourcesUpdatesTest extends RpkiTest {

  import scala.language.postfixOps

  test("Should update Child resources, extend certificate on request, and shrink again") {
    trustAnchor create()
    certificateAuthority create  ChildId
    trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
    certificateAuthority withId ChildId addParent  (current trustAnchor)
    certificateAuthority withId ChildId update

    (current certificateAuthority ChildId resourceClasses) should have size (1)

    def getCurrentChildCertificate = {
      val caRcWithCertificate = (current certificateAuthority ChildId resourceClasses).get(CertificateAuthority.DefaultResourceClassName).get
      caRcWithCertificate.currentSigner.signingMaterial.currentCertificate
    }

    getCurrentChildCertificate.getResources() should equal(ChildResources)

    trustAnchor updateChild (current certificateAuthority ChildId) withResources TrustAnchorResources
    getCurrentChildCertificate.getResources() should equal(ChildResources) // Entitled to more, but nothing re-issued yet

    certificateAuthority withId ChildId update

    // NOTE: revocation of old certificate is very hard to test here at this time. See SignerTest.scala
    getCurrentChildCertificate.getResources() should equal(TrustAnchorResources)

    trustAnchor updateChild (current certificateAuthority ChildId) withResources ChildResources
    certificateAuthority withId ChildId update

    current trustAnchor()

    getCurrentChildCertificate.getResources() should equal(ChildResources)
  }

  test("Should update Child resources, shrink to empty and revoke certificate on request, and grow again") {

    def getCurrentChildCertificate() = {
      val caRcWithCertificate = (current certificateAuthority ChildId resourceClasses).get(CertificateAuthority.DefaultResourceClassName).get
      caRcWithCertificate.currentSigner.signingMaterial.currentCertificate
    }

    def child() = certificateAuthority withId ChildId

    def validateChildRoas() = {
      val roas = child listRoas

      roas should have size(1)
      val roa = roas.head
      roa.getAsn should equal ("AS1": Asn)
      roa.getPrefixes should have size (1)
      roa.getPrefixes.get(0).getPrefix should equal ("192.168.0.0/24": IpRange)
      roa.getPrefixes.get(0).getEffectiveMaximumLength should equal (24)
    }

    def setUpTaAndChildWithResourcesAndRoa() = {
      trustAnchor create()
      certificateAuthority create ChildId
      trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
      child addParent (current trustAnchor)
      child update()
      child addRoaConfig(RoaAuthorisation(asn = "AS1", roaPrefix = "192.168.0.0/24"))
      child publish

      getCurrentChildCertificate.getResources() should equal(ChildResources)
    }

    def shrinkChild() = {
      trustAnchor updateChild (current certificateAuthority ChildId) withResources ""
      child update()
      (current certificateAuthority ChildId resourceClasses).get(CertificateAuthority.DefaultResourceClassName) should be(None)
    }

    def validateChildHasNoRoas() = {
      child listRoas() should have size(0)
    }

    def regrowChild() = {
      trustAnchor updateChild (current certificateAuthority ChildId) withResources ChildResources
      child update()
      getCurrentChildCertificate.getResources() should equal(ChildResources)
    }


    setUpTaAndChildWithResourcesAndRoa
    validateChildRoas

    shrinkChild
    validateChildHasNoRoas

    regrowChild
    validateChildRoas

  }

}
