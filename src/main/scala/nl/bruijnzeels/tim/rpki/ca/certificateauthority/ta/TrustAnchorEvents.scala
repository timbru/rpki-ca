package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta

import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event

sealed trait TrustAnchorEvent extends Event

case class TrustAnchorCreated(aggregateId: UUID, name: String) extends TrustAnchorEvent

