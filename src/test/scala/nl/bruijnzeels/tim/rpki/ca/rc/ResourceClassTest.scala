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
package nl.bruijnzeels.tim
package rpki
package ca
package rc

import java.net.URI
import java.util.UUID
import javax.security.auth.x500.X500Principal

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.common.domain.{KeyPairSupport, RpkiObjectNameSupport}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ResourceClassTest extends RpkiTest {

  import ResourceClassTest._

  test("Should created resource class") {
    RcWithSelfSignedSigner.children should have size (0)
    RcWithSelfSignedSigner.resourceClassName should equal(ResourceClassName)
    RcWithSelfSignedSigner.currentSigner should equal(SelfSignedSigner)
  }

  test("Should add child") {
    RcWithSelfSignedSigner.updateChild(ChildId, ChildResources) match {
      case Some(createEvent: ChildCreated) => {
        createEvent.childId should equal(ChildId)
        createEvent.entitledResources should equal(ChildResources)
        createEvent.resourceClassName should equal(ResourceClassName)
      }
      case _ => fail("Should have created child")
    }
  }

  test("Should NOT add child with resources not held") {
    try {
      RcWithSelfSignedSigner.updateChild(ChildId, "192.168.0.0/16")
      fail("Should have refused to create child")
    } catch {
      case ex: CertificateAuthorityException => // expected
    }
  }

  test("Should sign child request and store certificate") {
    val events = RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request)

    events should have size (2)
    val signed = events(0).asInstanceOf[SignerSignedCaCertificate]
    val received = events(1).asInstanceOf[ChildReceivedCertificate]
    signed.certificate should equal(received.certificate)
  }

  test("Should sign new child request revoke old certificate") {
    val firstSignEvents = RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request)
    val rcWithSignedChild = RcWithChild.applyEvents(firstSignEvents)
    val firstCertificate = firstSignEvents(1).asInstanceOf[ChildReceivedCertificate].certificate

    val secondSignEvents = rcWithSignedChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request)

    secondSignEvents should have size (4)
    val revoked = secondSignEvents(0).asInstanceOf[SignerAddedRevocation]
    revoked.revocation.serial should equal (firstCertificate.getSerialNumber)

    val removed = secondSignEvents(1).asInstanceOf[SignerRemovedCaCertificate]
    removed.certificate should equal(firstCertificate)
    
    val signed = secondSignEvents(2).asInstanceOf[SignerSignedCaCertificate]
    val received = secondSignEvents(3).asInstanceOf[ChildReceivedCertificate]
    signed.certificate should equal(received.certificate)
  }


  test("Should publish certificate for child") {
    val rcAfterPublish = RcWithCertifiedChild.applyEvents(RcWithCertifiedChild.publish())

    val set = rcAfterPublish.currentSigner.publicationSet
    set.items should have size (3) // mft, crl, cer
  }

}

object ResourceClassTest extends RpkiTest {

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

  val ChildAddedEvent = RcWithSelfSignedSigner.updateChild(ChildId, ChildResources).get

  val RcWithChild = RcWithSelfSignedSigner.applyEvent(ChildAddedEvent)

  val RcChildSignEvents = RcWithChild.processChildCertificateRequest(ChildId, Some(ChildResources), ChildPkcs10Request)

  val RcWithCertifiedChild = RcWithChild.applyEvents(RcChildSignEvents)

}