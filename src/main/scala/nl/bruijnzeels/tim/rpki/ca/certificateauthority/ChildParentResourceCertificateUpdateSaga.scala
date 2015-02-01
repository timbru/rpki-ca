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
package nl.bruijnzeels.tim.rpki.ca.certificateauthority

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca.CertificateAuthorityCommandDispatcher
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder

/**
 * Long running dialogue between two aggregates
 */
object ChildParentResourceCertificateUpdateSaga {

  def updateCertificates(trustAnchorId: UUID, certificateAuthorityId: UUID) = {
    var ta = TrustAnchorCommandDispatcher.load(trustAnchorId).getOrElse(throw new IllegalArgumentException("Can't find TA"))
    var ca = CertificateAuthorityCommandDispatcher.load(certificateAuthorityId).getOrElse(throw new IllegalArgumentException("Can't find CA"))

    val classListQuery = ca.createResourceClassListRequest()
    val classListResponse = ta.processListQuery(certificateAuthorityId, classListQuery)

    ta = classListResponse.updatedTa
    ca = ca.processResourceClassListResponse(classListQuery, classListResponse.response)

    val signRequests = ca.createCertificateIssuanceRequests

    signRequests.foreach { req =>
      val signResponse = ta.processCertificateIssuanceRequest(ca.versionedId.id, req)

      ta = signResponse.updatedTa
      ca = ca.processCeritificateIssuanceResponse(req, signResponse.response)
    }

    CertificateAuthorityCommandDispatcher.save(ca)
    TrustAnchorCommandDispatcher.save(ta)
  }

}