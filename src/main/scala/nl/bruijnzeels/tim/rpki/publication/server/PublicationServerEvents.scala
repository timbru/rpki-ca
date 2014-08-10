package nl.bruijnzeels.tim.rpki.publication.server

import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.messages.Delta

sealed trait PublicationServerEvent extends Event

case class PublicationServerCreated(aggregateId: UUID, sessionId: UUID) extends PublicationServerEvent
case class PublicationServerReceivedDelta(aggregateId: UUID, delta: Delta) extends PublicationServerEvent