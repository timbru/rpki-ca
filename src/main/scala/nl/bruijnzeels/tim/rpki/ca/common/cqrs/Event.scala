package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import java.util.UUID

trait Event {
  def id: UUID
}
