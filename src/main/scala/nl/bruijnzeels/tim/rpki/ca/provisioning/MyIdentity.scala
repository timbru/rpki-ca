package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate
import java.security.KeyPair
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilder
import javax.security.auth.x500.X500Principal

case class MyIdentity(id: UUID, identityCertificate: ProvisioningIdentityCertificate, keyPair: KeyPair) {
  
  def toChildIdentity() = new net.ripe.rpki.commons.provisioning.identity.ChildIdentity(id.toString, identityCertificate)
  
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