/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
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