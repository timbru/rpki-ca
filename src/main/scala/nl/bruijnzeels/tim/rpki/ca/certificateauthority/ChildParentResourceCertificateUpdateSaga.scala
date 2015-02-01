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