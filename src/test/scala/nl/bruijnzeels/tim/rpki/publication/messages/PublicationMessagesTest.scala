package nl.bruijnzeels.tim.rpki.publication.messages

import java.net.URI

import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassTest.SelfSignedSigner

import org.scalatest.FunSuite
import org.scalatest.Matchers

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PublicationMessagesTest extends FunSuite with Matchers {

  val certificate = SelfSignedSigner.signingMaterial.currentCertificate

  test("Should convert publication message to xml and back") {

    val publish = Publish(uri = URI.create("rsync://localhost/repo/ta.cer"), None, repositoryObject = certificate)
    val parsed = Publish.fromXml(publish.toXml)

    parsed should equal(publish)
  }

  test("Should convert publication message with replaces to xml and back") {

    val publish = Publish(uri = URI.create("rsync://localhost/repo/ta.cer"), replaces = Some(ReferenceHash.fromBytes(certificate.getEncoded)), repositoryObject = certificate)
    val parsed = Publish.fromXml(publish.toXml)

    parsed should equal(publish)
  }

  test("Should convert withdraw message to xml and back") {
    val withdraw = Withdraw.forRepositoryObject(uri = URI.create("rsync://localhost/repo/ta.cer"), repositoryObject = certificate)
    val parsed = Withdraw.fromXml(withdraw.toXml)

    parsed should equal(withdraw)
  }

  test("Should hash..") {
    val hash = ReferenceHash.fromBytes(certificate.getEncoded())
    hash.matches(certificate.getEncoded) should be(true)
  }

}