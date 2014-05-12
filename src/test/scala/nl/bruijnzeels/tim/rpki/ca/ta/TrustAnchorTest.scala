package nl.bruijnzeels.tim.rpki.ca.ta

import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import net.ripe.ipresource.IpResourceSet

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorTest extends FunSuite with Matchers {

  import TrustAnchorTest._

  test("Should reconstitute from events") {
    val ta = givenInitialisedTa

    ta.name should equal(TrustAnchorName)
    ta.keyPair should equal(Some(TrustAnchorKeyPair))
    ta.resources should equal(TrustAnchorResources: IpResourceSet)
    ta.events should have size (0)
  }

}

object TrustAnchorTest {

  val TrustAnchorName = "Test TA"
  val TrustAnchorResources = "10/8"
  val TrustAnchorKeyPair = KeyPairSupport.createRpkiKeyPair

  val created = TaCreated(TrustAnchorName)
  val resourcesUpdated = TaResourcesUpdated(TrustAnchorResources)
  val keyMade = TaKeyPairCreated(TrustAnchorKeyPair)

  def givenInitialisedTa: TrustAnchor = TrustAnchor.rebuild(List(created, resourcesUpdated, keyMade))
}
