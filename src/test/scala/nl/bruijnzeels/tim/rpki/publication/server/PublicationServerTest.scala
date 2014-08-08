package nl.bruijnzeels.tim.rpki.publication.server

import java.math.BigInteger
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassTest.SelfSignedSigner
import nl.bruijnzeels.tim.rpki.publication.messages.Publish
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.publication.messages.Withdraw

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PublicationServerTest extends FunSuite with Matchers {

  val PublicationServerId = UUID.fromString("170cd869-f729-47e7-9415-38b21da67ac1")

  test("Should initialise") {
    val server = PublicationServer.create(PublicationServerId)

    server.id should equal(PublicationServerId)
    server.sessionId should not be (null)
    server.serial should equal(BigInteger.ZERO)
  }

  test("Should publish") {
    val certificate = SelfSignedSigner.signingMaterial.currentCertificate
    val uri = SelfSignedSigner.signingMaterial.certificateUri

    val server = PublicationServer.create(PublicationServerId).publish(List(Publish.forRepositoryObject(uri, certificate)))

    server.serial should equal(BigInteger.ONE)
  }

  test("Should create snapshots and deltas") {
    val certificate = SelfSignedSigner.signingMaterial.currentCertificate
    val uri = SelfSignedSigner.signingMaterial.certificateUri
    val server = PublicationServer.create(PublicationServerId).publish(List(Publish.forRepositoryObject(uri, certificate)))

    server.snapshot.publishes should have size (1)
    server.deltas should have size (1)

    val serverAfterWithdraw = server.publish(List(Withdraw.forRepositoryObject(uri, certificate)))

    serverAfterWithdraw.snapshot.publishes should have size (0)
    serverAfterWithdraw.deltas should have size (2)
  }

  test("Should create notification file") {
    val certificate = SelfSignedSigner.signingMaterial.currentCertificate
    val uri = SelfSignedSigner.signingMaterial.certificateUri
    val server = PublicationServer.create(PublicationServerId).publish(List(Publish.forRepositoryObject(uri, certificate)))

    val notification = server.notificationFile

    notification.serial should equal(server.serial)
    notification.sessionId should equal(server.sessionId)
    notification.snapshots should have size (1)
    notification.deltas should have size (1)
  }

}