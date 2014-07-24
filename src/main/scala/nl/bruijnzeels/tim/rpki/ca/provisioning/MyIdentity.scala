package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.security.KeyPair
import java.util.UUID

import javax.security.auth.x500.X500Principal
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilder
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport

case class MyIdentity(id: UUID, identityCertificate: ProvisioningIdentityCertificate, keyPair: KeyPair) {
  
  def toChildXml() = {
    import net.ripe.rpki.commons.provisioning.identity._
    new ChildIdentitySerializer().serialize(new ChildIdentity(id.toString, identityCertificate))
  }
}

object MyIdentity {

  def create(id: UUID) = {
    val kp = KeyPairSupport.createRpkiKeyPair
    val cert = new ProvisioningIdentityCertificateBuilder()
      .withSelfSigningKeyPair(kp)
      .withSelfSigningSubject(new X500Principal("CN=" + id.toString))
      .build()

    MyIdentity(id = id, identityCertificate = cert, keyPair = kp)
  }

}