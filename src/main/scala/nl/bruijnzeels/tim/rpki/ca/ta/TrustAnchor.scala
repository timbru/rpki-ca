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

case class TrustAnchor(id: UUID, name: String, resourceClasses: Map[String, ResourceClass] = Map.empty, events: List[Event] = List.empty) extends AggregateRoot {

  def applyEvents(events: List[Event]): TrustAnchor = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: Event): TrustAnchor = event match {
    case resourceClassCreated: ResourceClassCreated => copy(resourceClasses = resourceClasses + (resourceClassCreated.resourceClassName -> ResourceClass.created(resourceClassCreated)), events = events :+ event)
    case resourceClassEvent: ResourceClassEvent => copy(resourceClasses = processRcEvent(resourceClassEvent), events = events :+ event)
    case _ => throw new UnknownEventException(event)
  }
  
  def clearEventList() = copy(events = List.empty)

  def processRcEvent(event: ResourceClassEvent) = resourceClasses.get(event.resourceClassName) match {
    case None => resourceClasses
    case Some(rc) => resourceClasses + (event.resourceClassName -> rc.applyEvent(event))
  }

}

object TrustAnchor {

  val DefaultResourceClassName = "default"

  def rebuild(events: List[Event]) = events.head match {
    case created: TrustAnchorCreated => TrustAnchor(id = created.aggregateId, name = created.name, events = List(created)).applyEvents(events.tail)
    case event: Event => throw new IllegalArgumentException(s"First event MUST be creation of the TrustAnchor, was: ${event}")
  }

  def create(aggregateId: UUID, name: String, taCertificateUri: URI, publicationDir: URI, resources: IpResourceSet) = {
    val taCreated = TrustAnchorCreated(aggregateId, name)
    val resourceClassCreatedEvent = ResourceClassCreated(aggregateId, DefaultResourceClassName)
    val createSignerEvents = Signer.createSelfSigned(aggregateId, DefaultResourceClassName, name, resources, taCertificateUri, publicationDir)

    rebuild(List(taCreated, resourceClassCreatedEvent) ++ createSignerEvents)
  }

}