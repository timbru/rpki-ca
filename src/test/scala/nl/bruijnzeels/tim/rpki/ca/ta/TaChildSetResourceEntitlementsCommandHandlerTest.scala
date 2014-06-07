package nl.bruijnzeels.tim.rpki.ca.ta

import net.ripe.ipresource.IpResourceSet

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TaChildSetResourceEntitlementsCommandHandlerTest extends TrustAnchorTest {

  test("Should add resource entitlement to child") {
    val command = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List(ResourceEntitlement("private use IP", IpResourceSet.IP_PRIVATE_USE_RESOURCES)))
    val ta = TaChildSetResourceEntitlementsCommandHandler.handle(command, givenTaWithChild)
    
    val child = ta.children(0)
    child.resourceClasses should have size (1)
    
    ta.events should have size (1)
    
    ta should equal(givenTaWithChild.applyEvents(ta.events))
  }
  
  test("Should remove resource class from child") {
    val addResourceClassCommand = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List(ResourceEntitlement("private use IP", IpResourceSet.IP_PRIVATE_USE_RESOURCES)))
    val taWithResourceClass = TaChildSetResourceEntitlementsCommandHandler.handle(addResourceClassCommand, givenTaWithChild)
    
    taWithResourceClass.children(0).resourceClasses should have size (1)
    
    val removeResourceClassCommand = TaChildSetResourceEntitlements(id = TrustAnchorId, childId = TrustAnchorChildId, entitlements = List.empty)
    val taWithoutResourceClass = TaChildSetResourceEntitlementsCommandHandler.handle(removeResourceClassCommand, taWithResourceClass)
    
    taWithoutResourceClass.children(0).resourceClasses should have size (0)
    
    taWithoutResourceClass should equal(givenTaWithChild.applyEvents(taWithoutResourceClass.events))
  }

}
