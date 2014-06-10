package nl.bruijnzeels.tim.rpki.ca.ta

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TaChildAddCommandHandlerTest extends TrustAnchorTest {

  test("Should add child") {
    val command = TaChildAdd(id = TrustAnchorId, childId = TrustAnchorChildId)
    val ta = TaChildAddCommandHandler.handle(command, givenInitialisedTa)
    
    ta.children should have size (1)
    val child = ta.children(0)
    
    child.id should equal(TrustAnchorChildId)
    child.resourceClasses should have size (0)
    
    ta should equal(givenInitialisedTa.applyEvents(ta.events))
  }

}
