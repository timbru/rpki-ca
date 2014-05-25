package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import java.math.BigInteger
import java.math.BigInteger

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TaPublishCommandHandlerTest extends TrustAnchorTest {

  test("Should create manifest and CRL for freshly initialised TA without other signed objects") {

    // given
    val ta = givenInitialisedTa

    // when
    val taAfterPublish = TaPublishCommandHandler.handle(TaPublish(ta.id), ta)

    // then
    val events = taAfterPublish.events

    events should have size (2)
    val published = events(1).asInstanceOf[TaPublicationSetUpdated]

    published.publicationSet.crl should not be (null)
    published.publicationSet.mft should not be (null)

    published.publicationSet.crl.getNumber() should be(BigInteger.ONE)
    published.publicationSet.crl.getRevokedCertificates() should have size (0)

    published.publicationSet.mft.getNumber() should be(BigInteger.ONE)
    published.publicationSet.mft.getFileNames() should have size (1)
    published.publicationSet.mft.getFileNames() should contain(RpkiObjectNameSupport.deriveName(published.publicationSet.crl))

    val mftCertificate = published.publicationSet.mft.getCertificate()
    mftCertificate.getSerialNumber() should equal(BigInteger.ONE)
    mftCertificate.isResourceSetInherited() should be(true)
  }

  test("Should create new manifest and CRL when publishing again") {

    // given
    val ta = givenInitialisedTa

    // when
    val taAfter1stPublish = TaPublishCommandHandler.handle(TaPublish(ta.id), ta)
    val taAfter2ndPublish = TaPublishCommandHandler.handle(TaPublish(ta.id), taAfter1stPublish)

    // then
    taAfter2ndPublish.events should have size (4)
    val first = taAfter2ndPublish.events(1).asInstanceOf[TaPublicationSetUpdated]
    val second = taAfter2ndPublish.events(3).asInstanceOf[TaPublicationSetUpdated]

    second.publicationSet.mft.getNumber() should equal(BigInteger.valueOf(2))
    second.publicationSet.mft.getCertificate().getSerialNumber() should equal(BigInteger.valueOf(2))
    second.publicationSet.crl.getNumber() should equal(BigInteger.valueOf(2))

  }

}
