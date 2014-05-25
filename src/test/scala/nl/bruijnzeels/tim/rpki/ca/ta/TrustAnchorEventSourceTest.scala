package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet

import org.scalatest.FunSuite
import org.scalatest.Matchers

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorEventSourceTest extends TrustAnchorTest {

  test("Should reconstitute from events") {
    val ta = givenInitialisedTa

    ta.name should equal(TrustAnchorName)
    ta.events should have size (0)
  }
}