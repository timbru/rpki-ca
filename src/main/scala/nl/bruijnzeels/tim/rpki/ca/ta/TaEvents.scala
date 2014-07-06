package nl.bruijnzeels.tim.rpki.ca.ta

import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event

sealed trait TaEvent extends Event

case class TaCreated(aggregateId: UUID, name: String) extends TaEvent

