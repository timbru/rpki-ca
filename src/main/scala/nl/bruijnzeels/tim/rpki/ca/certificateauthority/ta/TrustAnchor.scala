package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.AggregateRoot
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.UnknownEventException
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClass
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import java.util.UUID
import java.net.URI
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassCreated
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassCreated
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassEvent
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicator
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorCreated
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorEvent
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningMessageValidationFailure
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningMessageValidationSuccess
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayload
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayloadBuilder
import net.ripe.rpki.commons.provisioning.payload.common.GenericClassElementBuilder
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorPerformedChildExchange
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningChildExchange

/**
 * Root Certificate Authority for RPKI. Does not have a parent CA and has a self-signed certificate.
 */
case class TrustAnchor(
  id: UUID,
  name: String,
  resourceClass: ResourceClass = null,
  communicator: ProvisioningCommunicator = null,
  events: List[Event] = List.empty) extends AggregateRoot {

  def applyEvents(events: List[Event]): TrustAnchor = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: Event): TrustAnchor = event match {
    case resourceClassCreated: ResourceClassCreated => copy(resourceClass = ResourceClass.created(resourceClassCreated), events = events :+ event)
    case resourceClassEvent: ResourceClassEvent => copy(resourceClass = resourceClass.applyEvent(resourceClassEvent), events = events :+ event)
    case communicatorCreated: ProvisioningCommunicatorCreated => copy(communicator = ProvisioningCommunicator(communicatorCreated.myIdentity), events = events :+ event)
    case comminicatorEvent: ProvisioningCommunicatorEvent => copy(communicator = communicator.applyEvent(comminicatorEvent), events = events :+ event)
  }

  def clearEventList() = copy(events = List.empty)

  def publish(): TrustAnchor = applyEvents(resourceClass.publish)

  def addChild(childId: UUID, childXml: String, childResources: IpResourceSet): TrustAnchor = {
    resourceClass.addChild(childId, childResources) match {
      case Left(created) => applyEvents(List(created, communicator.addChild(id, childId, childXml)))
      case Right(failed) => throw new TrustAnchorException(failed.reason)
    }
  }

  /**
   * Will return a new TA that has the response registered with the child
   */
  def processListQuery(childId: UUID, request: ProvisioningCmsObject) = {
    communicator.validateMessage(childId, request) match {
      case failure: ProvisioningMessageValidationFailure => throw new TrustAnchorException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case query: ResourceClassListQueryPayload => {
            val builder = new ResourceClassListResponsePayloadBuilder()
            builder.addClassElement(resourceClass.buildClassResponseForChild(childId))
            val responsePayload = builder.build()

            val response = communicator.signResponse(childId, responsePayload)

            applyEvent(ProvisioningCommunicatorPerformedChildExchange(id, ProvisioningChildExchange(childId, request, response)))
          }
          case _ => throw new TrustAnchorException("Expected resource class list query")
        }
      }
    }

  }

}

object TrustAnchor {

  val DefaultResourceClassName = "default"

  def rebuild(events: List[Event]): TrustAnchor = events.head match {
    case created: TrustAnchorCreated => TrustAnchor(id = created.aggregateId, name = created.name, events = List(created)).applyEvents(events.tail)
    case event: Event => throw new IllegalArgumentException(s"First event MUST be creation of the TrustAnchor, was: ${event}")
  }

  def create(aggregateId: UUID, name: String, taCertificateUri: URI, publicationDir: URI, resources: IpResourceSet): TrustAnchor = {
    val taCreated = TrustAnchorCreated(aggregateId, name)
    val resourceClassCreatedEvent = ResourceClassCreated(aggregateId, DefaultResourceClassName)
    val createSignerEvents = Signer.createSelfSigned(aggregateId, DefaultResourceClassName, name, resources, taCertificateUri, publicationDir)
    val createProvisioningCommunicatorEvent = ProvisioningCommunicator.create(aggregateId)

    rebuild(List(taCreated, resourceClassCreatedEvent) ++ createSignerEvents :+ createProvisioningCommunicatorEvent)
  }
}

case class TrustAnchorException(msg: String) extends RuntimeException