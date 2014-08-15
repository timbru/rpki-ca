package nl.bruijnzeels.tim.rpki.publication.server

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.messages.Delta
import java.net.URI
import nl.bruijnzeels.tim.rpki.publication.messages.Snapshot
import nl.bruijnzeels.tim.rpki.publication.messages.Deltas

sealed trait PublicationServerEvent extends Event

case class PublicationServerCreated(aggregateId: UUID, sessionId: UUID, rrdpBaseUri: URI) extends PublicationServerEvent
case class PublicationServerReceivedSnapshot(aggregateId: UUID, snapshot: Snapshot) extends PublicationServerEvent
case class PublicationServerReceivedDeltas(aggregateId: UUID, deltas: Deltas) extends PublicationServerEvent