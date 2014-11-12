package nl.bruijnzeels.tim.rpki.publication.server

import java.net.URI
import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.messages.Delta
import nl.bruijnzeels.tim.rpki.publication.messages.Snapshot

sealed trait PublicationServerEvent extends Event

case class PublicationServerCreated(aggregateId: UUID, sessionId: UUID, rrdpBaseUri: URI) extends PublicationServerEvent
case class PublicationServerReceivedSnapshot(aggregateId: UUID, snapshot: Snapshot) extends PublicationServerEvent
case class PublicationServerReceivedDelta(aggregateId: UUID, delta: Delta) extends PublicationServerEvent