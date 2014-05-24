package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet

import org.scalatest.FunSuite
import org.scalatest.Matchers

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
  val TrustAnchorId = UUID.fromString("fdff6f65-1d4d-4940-8193-7c71911a2ec5")
  val TrustAnchorResources: IpResourceSet = "10/8"
  val TrustAnchorCertificateUri: URI = "rsync://localhost/ta.cer"
  val TrustAnchorPublicationUri: URI = "rsync://localhost/ta/"

  val created = TaCreated(TrustAnchorId, TrustAnchorName)
  val signerCreated = TaSigner.create(TrustAnchorId, TrustAnchorName, TrustAnchorResources, TrustAnchorCertificateUri, TrustAnchorPublicationUri)

  val TrustAnchorKeyPair = signerCreated.signingMaterial.keyPair

  def givenInitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created, signerCreated))
}
