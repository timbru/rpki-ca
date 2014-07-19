package nl.bruijnzeels.tim.rpki.ca.ta

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

case class TrustAnchor(id: UUID, name: String, resourceClass: Option[ResourceClass] = None, events: List[Event] = List.empty) extends AggregateRoot {

  def applyEvents(events: List[Event]): TrustAnchor = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: Event): TrustAnchor = event match {
    case resourceClassCreated: ResourceClassCreated => copy(resourceClass = Some(ResourceClass.created(resourceClassCreated)), events = events :+ event)
    case resourceClassEvent: ResourceClassEvent => copy(resourceClass = Some(resourceClass.get.applyEvent(resourceClassEvent)), events = events :+ event)
  }
  
  def clearEventList() = copy(events = List.empty)
  
  def publish(): TrustAnchor = resourceClass match {
    case None => this // nothing to do
    case Some(rc) => applyEvents(rc.publish)
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

    rebuild(List(taCreated, resourceClassCreatedEvent) ++ createSignerEvents)
  }

}