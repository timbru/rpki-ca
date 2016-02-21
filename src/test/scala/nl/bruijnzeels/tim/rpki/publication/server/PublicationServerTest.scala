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
package nl.bruijnzeels.tim.rpki.publication.server

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassTest.SelfSignedSigner
import nl.bruijnzeels.tim.rpki.publication.messages.{Publish, ReferenceHash, Withdraw}
import org.scalatest.{FunSuite, Matchers}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PublicationServerTest extends FunSuite with Matchers {

  val PublicationServerId = UUID.fromString("170cd869-f729-47e7-9415-38b21da67ac1")
  val RrdpBaseUrl = URI.create("http://localhost:8080/rrdp/")

  test("Should initialise") {
    val server = PublicationServer.create(PublicationServerId, RrdpBaseUrl)

    server.versionedId.id should equal(PublicationServerId)
    server.sessionId should not be (null)
    server.serial should equal(BigInteger.ZERO)
  }

  test("Should publish") {
    val certificate = SelfSignedSigner.signingMaterial.currentCertificate
    val uri = SelfSignedSigner.signingMaterial.certificateUri

    val server = PublicationServer.create(PublicationServerId, RrdpBaseUrl).publish(List(Publish.forRepositoryObject(uri, certificate)))

    server.serial should equal(BigInteger.ONE)
  }

  test("Should create snapshots and deltas") {
    val certificate = SelfSignedSigner.signingMaterial.currentCertificate
    val uri = SelfSignedSigner.signingMaterial.certificateUri
    val server = PublicationServer.create(PublicationServerId, RrdpBaseUrl).publish(List(Publish.forRepositoryObject(uri, certificate)))

    server.snapshot.publishes should have size (1)
    server.deltas should have size (1)

    val serverAfterWithdraw = server.publish(List(Withdraw.forRepositoryObject(uri, certificate)))

    serverAfterWithdraw.snapshot.publishes should have size (0)
    serverAfterWithdraw.deltas should have size (2)
  }

  test("Should create notification file") {
    val certificate = SelfSignedSigner.signingMaterial.currentCertificate
    val uri = SelfSignedSigner.signingMaterial.certificateUri
    val server = PublicationServer.create(PublicationServerId, RrdpBaseUrl).publish(List(Publish.forRepositoryObject(uri, certificate)))

    val notification = server.notificationFile

    notification.serial should equal(server.serial)
    notification.sessionId should equal(server.sessionId)
    notification.snapshot.hash should equal(ReferenceHash.fromXml(server.snapshot.toXml))
    notification.deltas should have size (1)
    notification.deltas.head.hash should equal(ReferenceHash.fromXml(server.deltas.head.toXml))
  }

}