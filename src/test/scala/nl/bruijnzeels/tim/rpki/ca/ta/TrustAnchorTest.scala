package nl.bruijnzeels.tim.rpki.ca.ta

import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import net.ripe.ipresource.IpResourceSet
import java.net.URI

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorTest extends FunSuite with Matchers {

  import TrustAnchorTest._

  test("Should reconstitute from events") {
    val ta = givenInitialisedTa

    ta.name should equal(TrustAnchorName)
    ta.events should have size (0)
  }

}

object TrustAnchorTest {

  val TrustAnchorName = "root"
  val TrustAnchorResources: IpResourceSet = "10/8"
  val TrustAnchorCertificateUri: URI = "rsync://localhost/ta.cer"
  val TrustAnchorPublicationUri: URI = "rsync://localhost/ta/"

  val created = TaCreated(TrustAnchorName)
  val signerCreated = TaSigner.create(TrustAnchorName, TrustAnchorResources, TrustAnchorCertificateUri, TrustAnchorPublicationUri)
  
  val TrustAnchorKeyPair = signerCreated.signingCertificate.keyPair
  
  def givenInitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created, signerCreated))
}
