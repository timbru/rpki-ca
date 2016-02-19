/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
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
package nl.bruijnzeels.tim
package rpki
package ca
package rc

import java.net.URI
import java.util.UUID

import org.scalatest.FunSuite
import org.scalatest.Matchers

import javax.security.auth.x500.X500Principal
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildCreated
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildReceivedCertificate
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerSignedCertificate
import nl.bruijnzeels.tim.rpki.ca.stringToIpResourceSet
import nl.bruijnzeels.tim.rpki.ca.stringToUri

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ResourceClassTest extends FunSuite with Matchers {

  import ResourceClassTest._

  test("Should created resource class") {
    RcWithSelfSignedSigner.children should have size (0)
    RcWithSelfSignedSigner.resourceClassName should equal(ResourceClassName)
    RcWithSelfSignedSigner.currentSigner should equal(SelfSignedSigner)
  }

  test("Should add child") {
    RcWithSelfSignedSigner.addChild(ChildId, ChildResources) match {
      case Left(createEvent) => {
        createEvent.childId should equal(ChildId)
        createEvent.entitledResources should equal(ChildResources)
        createEvent.resourceClassName should equal(ResourceClassName)
      }
      case _ => fail("Should have created  child")
    }
  }

  test("Should NOT add child with resources not held") {
    RcWithSelfSignedSigner.addChild(ChildId, "192.168.0.0/16") match {
      case Right(failedEvent) =>
      case _ => fail("Should have refused to create child")
    }
  }

  test("Should sign child request and store certificate") {
    RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request) match {
      case Right(error) => fail("Should sign request")
      case Left(events) => {
        events should have size (2)
        val signed = events(0).asInstanceOf[SignerSignedCertificate]
        val received = events(1).asInstanceOf[ChildReceivedCertificate]
        signed.certificate should equal(received.certificate)
      }
    }
  }

  test("Should publish certificate for child") {
    val rcAfterPublish = RcWithCertifiedChild.applyEvents(RcWithCertifiedChild.publish())

    val set = rcAfterPublish.currentSigner.publicationSet
    set.items should have size (3) // mft, crl, cer
  }

}

object ResourceClassTest {

  val AggregateId = UUID.fromString("3e13717b-da5b-4371-a8c1-45d390fd8dc7")
  val ResourceClassName = "test resource class"

  val RrdpNotifyUri: URI = "http://localhost:8080/rrdp/notify.xml"

  val SignerName = "test signer"
  val SignerSubject = new X500Principal("CN=" + SignerName)
  val SignerResources: IpResourceSet = "10.0.0.0/8"
  val SignerPublicationDir: URI = "rsync://host/some/dir"
  val SignerCertificateUri: URI = "rsync://host/ta/ta.cer"

  val ChildId = UUID.fromString("b716cfff-a58c-426c-81bf-096ae78abed7")
  val ChildPublicationUri: URI = s"rsync://localhost/${ChildId}/"
  val ChildPublicationMftUri: URI = ChildPublicationUri.resolve("child.mft")
  val ChildKeyPair = KeyPairSupport.createRpkiKeyPair
  val ChildSubject = RpkiObjectNameSupport.deriveSubject(ChildKeyPair.getPublic())
  val ChildResources: IpResourceSet = "10.0.0.0/24"

  val ChildCreatedEvent = ChildCreated(resourceClassName = ResourceClassName, childId = ChildId, entitledResources = ChildResources)

  val ChildPkcs10Request = new RpkiCaCertificateRequestBuilder()
    .withCaRepositoryUri(ChildPublicationUri)
    .withManifestUri(ChildPublicationMftUri)
    .withNotificationUri(RrdpNotifyUri)
    .withSubject(ChildSubject)
    .build(ChildKeyPair)

  val SelfSignedSignerCreatedEvents = Signer.createSelfSigned(ResourceClassName, SignerName, SignerResources, SignerCertificateUri, SignerPublicationDir, RrdpNotifyUri)

  val SelfSignedSigner = Signer.buildFromEvents(SelfSignedSignerCreatedEvents)

  val RcCreatedEvent = ResourceClassCreated(ResourceClassName)

  val RcWithSelfSignedSigner = ResourceClass.created(RcCreatedEvent).applyEvents(SelfSignedSignerCreatedEvents)

  val ChildAddedEvent = RcWithSelfSignedSigner.addChild(ChildId, ChildResources).left.get

  val RcWithChild = RcWithSelfSignedSigner.applyEvent(ChildAddedEvent)

  val RcChildSignEvents = RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request).left.get

  val RcWithCertifiedChild = RcWithChild.applyEvents(RcChildSignEvents)

}