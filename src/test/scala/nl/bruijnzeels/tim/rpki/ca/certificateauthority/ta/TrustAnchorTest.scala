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
package certificateauthority.ta

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayload
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport
import nl.bruijnzeels.tim.rpki.ca.provisioning.MyIdentity
import org.scalatest.{FunSuite, Matchers}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorTest extends FunSuite with Matchers {

import TrustAnchorTest._

  test("Should create TA with selfsigned signer and provisioning communicator") {

    val create = TrustAnchorCreate(
      aggregateId = TrustAnchorId,
      name = TrustAnchorName,
      resources = TrustAnchorResources,
      taCertificateUri = TrustAnchorCertUri,
      publicationUri = TrustAnchorPubUri,
      rrdpNotifyUrl = RrdpNotifyUrl)

    val ta = TrustAnchorCreateCommandHandler.handle(create)

    val rc = ta.resourceClass
    val signingMaterial = rc.currentSigner.signingMaterial
    val certificate = signingMaterial.currentCertificate

    signingMaterial.certificateUri should equal(TrustAnchorCertUri)
    certificate.getResources() should equal(TrustAnchorResources)
    certificate.getRepositoryUri() should equal(TrustAnchorPubUri)
    certificate.getRrdpNotifyUri() should equal(RrdpNotifyUrl)

    ta.communicator should not be (None)
    ta.communicator.me.id should equal(TrustAnchorId)
    ta.communicator.children should have size (0)

    ta should equal(TrustAnchor.rebuild(ta.events))
  }

  test("Should publish") {
    val ta = TrustAnchorInitial.publish

    // Publishing is tested in more detail elsewhere, here I just want to verify that it's done
    val set = ta.resourceClass.currentSigner.publicationSet
    set.number should equal(BigInteger.ONE)

    ta should equal(TrustAnchor.rebuild(ta.events))
  }

  test("Should add child") {
    val addChild = TrustAnchorAddChild(versionedId = TrustAnchorInitial.versionedId, childId = ChildId, childXml = ChildXml, childResources = ChildResources)

    val taWithChild = TrustAnchorAddChildCommandHandler.handle(addChild, TrustAnchorInitial)

    taWithChild.communicator.children.isDefinedAt(ChildId) should be(true)
    taWithChild.resourceClass.children.isDefinedAt(ChildId) should be(true)
  }

  test("Should process child resource class list query") {
    val addChild = TrustAnchorAddChild(versionedId = TrustAnchorInitial.versionedId, childId = ChildId, childXml = ChildXml, childResources = ChildResources)
    val taWithChild = TrustAnchorAddChildCommandHandler.handle(addChild, TrustAnchorInitial)

    val request = SigningSupport.createProvisioningCms(
      sender = ChildId.toString,
      recipient = TrustAnchorId.toString,
      signingCertificate = ChildIdentity.identityCertificate,
      signingKeyPair = ChildIdentity.keyPair,
      payload = new ResourceClassListQueryPayloadBuilder().build())

    val command = TrustAnchorProcessResourceListQuery(taWithChild.versionedId, ChildId, request)

    val taAfterResponse = TrustAnchorProcessResourceListQueryCommandHandler.handle(command, taWithChild)

    val exchange = taAfterResponse.communicator.getExchangesForChild(ChildId)(0)

    val responsePayload = exchange.response.getPayload().asInstanceOf[ResourceClassListResponsePayload]
    responsePayload.getSender should equal (TrustAnchorId.toString())
    responsePayload.getRecipient should equal (ChildId.toString())

    val resourceClassInResponse = responsePayload.getClassElements().get(0)
    resourceClassInResponse.getCertificateElements() should be (null)
    resourceClassInResponse.getClassName() should equal (TrustAnchor.DefaultResourceClassName)
    resourceClassInResponse.getResourceSetIpv4() should equal (ChildResources)
    resourceClassInResponse.getResourceSetIpv6() should equal(new IpResourceSet())
    resourceClassInResponse.getResourceSetAsn() should equal(new IpResourceSet())
  }

}

object TrustAnchorTest {

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

  val TrustAnchorInitial =
    TrustAnchorCreateCommandHandler.handle(
      TrustAnchorCreate(
        aggregateId = TrustAnchorId,
        name = TrustAnchorName,
        resources = TrustAnchorResources,
        taCertificateUri = TrustAnchorCertUri,
        publicationUri = TrustAnchorPubUri,
        rrdpNotifyUrl = RrdpNotifyUrl))

}