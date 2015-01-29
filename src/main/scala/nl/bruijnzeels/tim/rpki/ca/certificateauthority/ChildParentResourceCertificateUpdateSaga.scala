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
    val ta = TrustAnchorCommandDispatcher.load(trustAnchorId).getOrElse(throw new IllegalArgumentException("Can't find TA"))
    val ca = CertificateAuthorityCommandDispatcher.load(certificateAuthorityId).getOrElse(throw new IllegalArgumentException("Can't find CA"))

    val classListQuery = ca.communicator.signRequest(new ResourceClassListQueryPayloadBuilder().build())

    val taAfterListQuery = ta.processListQuery(certificateAuthorityId, classListQuery)

    // Create resource classes with pending certificate requests as needed
    val classListResponse = taAfterListQuery.communicator.getExchangesForChild(certificateAuthorityId).last.response
    val caWithRequests = ca.processResourceClassListResponse(classListQuery, classListResponse)

    // Let the CA request certificates for each resource class that wants one
    val resourceClassesWithRequests = caWithRequests.resourceClasses.values.filter(_.currentSigner.pendingCertificateRequest.isDefined)
    val caTaTuple = resourceClassesWithRequests.foldLeft((caWithRequests, taAfterListQuery)) { (caTaTuple, rc) =>
      val ca = caTaTuple._1
      val ta = caTaTuple._2
      
      val request = ca.communicator.signRequest(rc.currentSigner.pendingCertificateRequest.get)
        
      val taAfterIssuanceResponse = ta.processResourceCertificateIssuanceRequest(ca.versionedId.id, request)
      val caAfterIssuanceResponse = ca.processCeritificateIssuanceResponse(request, taAfterIssuanceResponse.communicator.getExchangesForChild(ca.versionedId.id).last.response)
        
      (caAfterIssuanceResponse, taAfterIssuanceResponse)
    }
    
    CertificateAuthorityCommandDispatcher.save(caTaTuple._1)
    TrustAnchorCommandDispatcher.save(caTaTuple._2)

  }

}