package nl.bruijnzeels.tim.rpki.ca
package ta

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.net.URI
import net.ripe.ipresource.IpResourceSet
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import javax.security.auth.x500.X500Principal
import java.math.BigInteger

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorTest extends FunSuite with Matchers {

  import TrustAnchorTest._

  test("Should create TA with selfsigned signer") {

    val create = TrustAnchorCreate(
      id = TrustAnchorId,
      name = TrustAnchorName,
      resources = TrustAnchorResources,
      taCertificateUri = TrustAnchorCertUri,
      publicationUri = TrustAnchorPubUri)

    val ta = TrustAnchorCreateCommandHandler.handle(create)

    val rc = ta.resourceClasses.get(TrustAnchor.DefaultResourceClassName).get
    val signingMaterial = rc.currentSigner.signingMaterial
    val certificate = signingMaterial.currentCertificate

    signingMaterial.certificateUri should equal(TrustAnchorCertUri)
    certificate.getResources() should equal(TrustAnchorResources)
    certificate.getRepositoryUri() should equal(TrustAnchorPubUri)

    ta should equal(TrustAnchor.rebuild(ta.events))
  }

  test("Should publish") {
    val ta = TrustAnchorInitial.publish
    
    // Publishing is testing in more detail elsewhere, here I just want to verify that it's done
    val set = ta.resourceClasses.get(TrustAnchor.DefaultResourceClassName).get.currentSigner.publicationSet.get
    set.number should equal (BigInteger.ONE)
    
    ta should equal(TrustAnchor.rebuild(ta.events))
  }

}

object TrustAnchorTest {

  val TrustAnchorId = UUID.fromString("f3ec94ee-ae80-484a-8d58-a1e43bbbddd1")
  val TrustAnchorName = "TA"
  val TrustAnchorCertUri: URI = "rsync://host/ta/ta.cer"
  val TrustAnchorPubUri: URI = "rsync://host/repository/"
  val TrustAnchorResources = IpResourceSet.ALL_PRIVATE_USE_RESOURCES

  val TrustAnchorInitial =
    TrustAnchorCreateCommandHandler.handle(
      TrustAnchorCreate(
        id = TrustAnchorId,
        name = TrustAnchorName,
        resources = TrustAnchorResources,
        taCertificateUri = TrustAnchorCertUri,
        publicationUri = TrustAnchorPubUri))

}