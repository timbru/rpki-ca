package nl.bruijnzeels.tim.rpki.ca.certificateauthority

import scala.language.postfixOps

import nl.bruijnzeels.tim.rpki.ca.RpkiCaTest
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchor
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.ChildId
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.ChildResources
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.certificateAuthority
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.create
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.current
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.trustAnchor

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ChildParentResourceCertificateUpdateSagaTest extends RpkiCaTest {

  test("Child should get certificate from TA") {
    create trustAnchor ()
    create certificateAuthority ChildId
    trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
    certificateAuthority withId ChildId addTa (current trustAnchor)
    certificateAuthority withId ChildId update

    (current certificateAuthority ChildId resourceClasses) should have size (1)
    val caRcWithCertificate = (current certificateAuthority ChildId resourceClasses).get(TrustAnchor.DefaultResourceClassName).get
    val caCertificate = caRcWithCertificate.currentSigner.signingMaterial.currentCertificate

    caCertificate.getResources() should equal(ChildResources)
  }

}