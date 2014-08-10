package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import java.util.UUID

trait AggregateRoot {
  def id: UUID // TODO: Have versions to detect concurrent updates
  def applyEvents(events: List[Event]): AggregateRoot
  def clearEventList(): AggregateRoot
}