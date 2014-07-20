package nl.bruijnzeels.tim.rpki.ca.provisioning

import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectValidator
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.validation.ValidationOptions
import org.apache.commons.lang3.StringUtils
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload

object ProvisioningMessageValidation {

  /**
   * Validate a provisioning CMS message
   */
  def validate(cmsObject: ProvisioningCmsObject, expectedSender: String, expectedSigningCertificate: ProvisioningIdentityCertificate) = {
    val validator = new ProvisioningCmsObjectValidator(new ValidationOptions(), cmsObject, expectedSigningCertificate)
    val result = ValidationResult.withLocation("cms")
    validator.validate(result)
    if (!result.hasFailures()) {
      val payload = cmsObject.getPayload()
      if (StringUtils.equals(payload.getSender(), expectedSender)) {
        ProvisioningMessageValidationSuccess(payload)
      } else {
        ProvisioningMessageValidationFailure("Sender handle does not match expected identity")
      }
    } else {
      ProvisioningMessageValidationFailure("Provisionign CMS failed validation: " + result)
    }
  }

}

sealed trait ProvisioningMessageValidationResult

case class ProvisioningMessageValidationSuccess(payload: AbstractProvisioningPayload) extends ProvisioningMessageValidationResult
case class ProvisioningMessageValidationFailure(reason: String) extends ProvisioningMessageValidationResult