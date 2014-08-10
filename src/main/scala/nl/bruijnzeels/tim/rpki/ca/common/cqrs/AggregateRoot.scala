package nl.bruijnzeels.tim.rpki.ca.common.cqrs

trait AggregateRoot {
  def applyEvents(events: List[Event]): AggregateRoot
  def clearEventList(): AggregateRoot
}