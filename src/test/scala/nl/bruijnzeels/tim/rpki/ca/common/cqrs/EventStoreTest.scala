package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import org.scalatest.Finders
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServer
import java.util.UUID

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class EventStoreTest extends FunSuite with Matchers {

  test("Should let listener subscribe to new events") {

    case class TestEvent(aggregateId: UUID) extends Event
    val events = List(TestEvent(UUID.randomUUID()))

    val listener = new EventListener {
      override def handle(events: List[Event]) = { events should equal (events) }
    }
    EventStore.subscribe(listener)

    EventStore.store(events);
  }

}