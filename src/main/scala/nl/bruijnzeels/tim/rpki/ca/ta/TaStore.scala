package nl.bruijnzeels.tim.rpki.ca.ta

import java.util.UUID

object TaStore {
  
  def load(id: UUID): Option[TrustAnchor] = {
    val events = TaEventStore.retrieve(id)
    if (events.size == 0) {
      None
    } else {
      Some(TrustAnchor.rebuild(events))
    }
  }
  
  def save(ta: TrustAnchor) = {
    TaEventStore.store(ta.events)
  }

}

object TaEventStore {
  
  // TODO: Have a nice thread safe event store. Use STM?
  var eventList: List[TaEvent] = List.empty
  
  def retrieve(aggregateId: UUID): List[TaEvent] = eventList.filter(_.id == aggregateId)
  def store(events: List[TaEvent]): Unit = eventList = eventList ++ events
  def clear(): Unit = eventList = List.empty
}