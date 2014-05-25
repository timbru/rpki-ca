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

  test("Should fail with sensible error if the ta is not initialised") {
    val ta = givenUninitialisedTa
    val e = intercept[TrustAnchorException] { TaPublishCommandHandler.handle(TaPublish(ta.id), ta) }
    e.getMessage() should equal("Trying to publish before initialising TrustAnchor")
  }

  test("Should create manifest and CRL for freshly initialised TA without other signed objects") {

    // given
    val ta = givenInitialisedTa

    // when
    val taAfterPublish = TaPublishCommandHandler.handle(TaPublish(ta.id), ta)

    // then
    val publicationSet = taAfterPublish.signer.get.publicationSet.get

    publicationSet.crl should not be (null)
    publicationSet.mft should not be (null)

    publicationSet.crl.getNumber() should be(BigInteger.ONE)
    publicationSet.crl.getRevokedCertificates() should have size (0)

    publicationSet.mft.getNumber() should be(BigInteger.ONE)
    publicationSet.mft.getFileNames() should have size (1)
    publicationSet.mft.getFileNames() should contain(RpkiObjectNameSupport.deriveName(publicationSet.crl))

    val mftCertificate = publicationSet.mft.getCertificate()
    mftCertificate.getSerialNumber() should equal(BigInteger.ONE)
    mftCertificate.isResourceSetInherited() should be(true)

    // make sure that the events can be re-applied
    taAfterPublish should equal(givenInitialisedTa.applyEvents(taAfterPublish.events))
  }

  test("Should create new manifest and CRL when publishing again") {

    // given
    val ta = givenInitialisedTa
    val taAfter1stPublish = TaPublishCommandHandler.handle(TaPublish(ta.id), ta)

    // when
    val taAfter2ndPublish = TaPublishCommandHandler.handle(TaPublish(ta.id), taAfter1stPublish)

    // then
    val signerFor2nd = taAfter2ndPublish.signer.get
    val publicationSetFor2nd = signerFor2nd.publicationSet.get

    val signerFor1st = taAfter1stPublish.signer.get
    val publicationSetFor1st = signerFor1st.publicationSet.get

    publicationSetFor2nd.mft.getNumber() should equal(BigInteger.valueOf(2))
    publicationSetFor2nd.mft.getCertificate().getSerialNumber() should equal(BigInteger.valueOf(2))

    publicationSetFor2nd.crl.getNumber() should equal(BigInteger.valueOf(2))
    publicationSetFor2nd.crl.getRevokedCertificates() should have size (1)
    publicationSetFor2nd.crl.isRevoked(publicationSetFor1st.mft.getCertificate().getCertificate()) should be(true)
    publicationSetFor2nd.crl.isRevoked(publicationSetFor2nd.mft.getCertificate().getCertificate()) should be(false)

    // make sure that the events can be re-applied
    taAfter2ndPublish should equal(givenInitialisedTa.applyEvents(taAfter2ndPublish.events))
  }

}
