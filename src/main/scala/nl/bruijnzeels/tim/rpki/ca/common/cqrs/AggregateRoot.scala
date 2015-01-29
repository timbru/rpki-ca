package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import java.util.UUID

trait AggregateRoot {
  def versionedId: VersionedId
  def applyEvents(events: List[Event]): AggregateRoot
  def clearEventList(): AggregateRoot
}

case class VersionedId(id: UUID, version: Long = 0) {
  def next = VersionedId(id, version + 1)
}