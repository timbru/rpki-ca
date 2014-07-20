package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectValidator
import net.ripe.rpki.commons.validation.ValidationOptions
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload

case class ChildIdentity(childId: UUID, identityCertificate: ProvisioningIdentityCertificate) {

  def validateMessage(cmsObject: ProvisioningCmsObject) = 
    ProvisioningMessageValidation.validate(cmsObject, childId.toString(), identityCertificate)

}

object ChildIdentity {

  def fromXml(xml: String) =
    ChildIdentity(childId = UUID.randomUUID(), identityCertificate = new ChildIdentitySerializer().deserialize(xml).getIdentityCertificate())

}