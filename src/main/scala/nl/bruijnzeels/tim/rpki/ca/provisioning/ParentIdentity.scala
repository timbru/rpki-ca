package nl.bruijnzeels.tim.rpki.ca.provisioning

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate
import net.ripe.rpki.commons.provisioning.identity.ParentIdentitySerializer
import java.net.URI

case class ParentIdentity(parentHandle: String, myHandle: String, identityCertificate: ProvisioningIdentityCertificate, provisioningUrl: URI) {

}

object ParentIdentity {

  def fromXml(parentXml: String) = {
    val parent = new ParentIdentitySerializer().deserialize(parentXml)
    ParentIdentity(
      parentHandle = parent.getParentHandle(),
      myHandle = parent.getChildHandle(),
      identityCertificate = parent.getParentIdCertificate(),
      provisioningUrl = parent.getUpDownUrl())
  }

}