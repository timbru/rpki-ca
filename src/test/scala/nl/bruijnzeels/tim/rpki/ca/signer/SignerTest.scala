package nl.bruijnzeels.tim.rpki
package ca
package signer

import org.scalatest.FunSuite
import java.util.UUID
import net.ripe.ipresource.IpResource
import net.ripe.ipresource.IpResourceSet
import java.net.URI
import org.scalatest.Matchers
import javax.security.auth.x500.X500Principal

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class SignerTest extends FunSuite with Matchers {

  val AggregateId = UUID.fromString("3e13717b-da5b-4371-a8c1-45d390fd8dc7")
  val Name = "test signer"
  val Subject = new X500Principal("CN=" + Name)
  val Resources: IpResourceSet = "10/8"
  val PublicationDir: URI = "rsync://host/some/dir"

  test("should create self-signed signer") {
    val taCertificateUri: URI = "rsync://host/ta/ta.cer"

    val signerEvents = Signer.createSelfSigned(AggregateId, Name, Resources, taCertificateUri, PublicationDir)
    val signer = Signer.buildFromEvents(signerEvents)

    val signerCertificate = signer.signingMaterial.currentCertificate
    signerCertificate should not be (null)
    signerCertificate.getResources() should equal(Resources)
    signerCertificate.getIssuer() should equal(Subject)
    signerCertificate.getSubject() should equal(Subject)
  }

}