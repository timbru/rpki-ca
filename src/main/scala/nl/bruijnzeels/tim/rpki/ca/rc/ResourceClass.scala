package nl.bruijnzeels.tim.rpki.ca.rc

import java.util.UUID
import scala.util.Either
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.rc.child.Child
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildCreated
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerEvent
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import nl.bruijnzeels.tim.rpki.ca.rc.child.ChildReceivedCertificate

/**
 * The name for this class: ResourceClass is taken from the "Provisioning Resource Certificates" Protocol.
 * See: http://tools.ietf.org/html/rfc6492
 *
 * Essentially a Certificate Authority as a logical entity may not get all their resources in a single bundle.
 * Instead resources may be grouped in what are called resource classes.
 *
 */
case class ResourceClass(aggregateId: UUID, resourceClassName: String, currentSigner: Signer, children: Map[UUID, Child] = Map.empty) {

  def applyEvents(events: List[ResourceClassEvent]): ResourceClass = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: ResourceClassEvent): ResourceClass = event match {
    case signerEvent: SignerEvent => copy(currentSigner = currentSigner.applyEvent(signerEvent))
    case childCreated: ChildCreated => copy(children = children + (childCreated.childId -> Child.created(childCreated)))
  }

  def isOverclaiming(resources: IpResourceSet) = {
    val overclaiming = new IpResourceSet(resources) // Don't modify input..
    overclaiming.removeAll(currentSigner.resources)
    !overclaiming.isEmpty
  }

  def addChild(childId: UUID, entitledResources: IpResourceSet): Either[ChildCreated, ResourceClassError] = {
    if (!isOverclaiming(entitledResources)) {
      Left(ChildCreated(aggregateId = aggregateId, resourceClassName = resourceClassName, childId = childId, entitledResources = entitledResources))
    } else {
      Right(CannotAddChildWithOverclaimingResources)
    }
  }

  def processChildCertificateRequest(childId: UUID, requestedResources: Option[IpResourceSet], pkcs10Request: PKCS10CertificationRequest): Either[List[ResourceClassEvent], ResourceClassError] = {

    children.get(childId) match {
      case None => Right(UnknownChild(childId))
      case Some(child) => {
        val resources = requestedResources.getOrElse(child.entitledResources)
        if (! child.entitledResources.contains(resources)) {
          Right(ChildDoesNotHaveAllResources(resources))
        } else {
          currentSigner.signChildCertificateRequest(aggregateId, resourceClassName, resources, pkcs10Request) match {
            case Left(signed) => 
              Left(List(signed, ChildReceivedCertificate(aggregateId, resourceClassName, childId, signed.certificate)))
            case Right(error) => Right(error)
          }
        }
      }
    }

  }

}

object ResourceClass {
  def created(created: ResourceClassCreated) = ResourceClass(aggregateId = created.aggregateId, resourceClassName = created.resourceClassName, currentSigner = created.currentSigner)
}