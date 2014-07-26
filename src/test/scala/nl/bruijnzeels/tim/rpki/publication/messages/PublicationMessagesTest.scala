package nl.bruijnzeels.tim.rpki.publication.messages

import org.scalatest.FunSuite
import org.scalatest.Matchers
import java.net.URI
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassTest
import scala.xml.Elem
import scala.xml.XML
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import sun.misc.BASE64Decoder
import net.ripe.rpki.commons.validation.ValidationResult
import sun.misc.BASE64Encoder

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PublicationMessagesTest extends FunSuite with Matchers {
  
  import ResourceClassTest._
  val certificate = SelfSignedSigner.signingMaterial.currentCertificate
  
  test("Should convert publication message to xml and back") {
    
    val publish = Publish(uri=URI.create("rsync://localhost/repo/ta.cer"), repositoryObject = certificate)
    val parsed = Publish.fromXml(publish.toXml)

    parsed should equal (publish)
  }
  
  test("Should convert withdraw message to xml and back") {
    val withdraw = Withdraw(uri=URI.create("rsync://localhost/repo/ta.cer"))
    val parsed = Withdraw.fromXml(withdraw.toXml)
    
    parsed should equal(withdraw)
  }
  
  test("Should hash..") {
    val hash = ReferenceHash.fromBytes(certificate.getEncoded())
    hash.matches(certificate.getEncoded) should be (true)
  }

}